# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import time

import eventlet
from ironicclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd.plugins import base as plugins_base
from ironic_discoverd import utils


LOG = logging.getLogger("discoverd")


def process(node_info):
    """Process data from discovery ramdisk."""
    hooks = plugins_base.processing_hooks_manager()
    for hook_ext in hooks:
        hook_ext.obj.pre_discover(node_info)

    bmc_address = node_info.get('ipmi_address')

    cached_node = node_cache.pop_node(bmc_address=bmc_address,
                                      mac=node_info.get('macs'))
    ironic = utils.get_client()
    try:
        node = ironic.node.get(cached_node.uuid)
    except exceptions.NotFound as exc:
        LOG.error('Node UUID %(uuid)s is in the cache, but not found '
                  'in Ironic: %(exc)s',
                  {'uuid': cached_node.uuid, 'exc': exc})
        raise utils.DiscoveryFailed('Node UUID %s was found is cache, '
                                    'but is not found in Ironic' %
                                    cached_node.uuid,
                                    code=404)

    if not node.extra.get('on_discovery'):
        LOG.error('Node is not on discovery, cannot proceed')
        raise utils.DiscoveryFailed('Node %s is not on discovery' %
                                    cached_node.uuid,
                                    code=403)

    updated = _process_node(ironic, node, node_info, cached_node)
    return {'node': updated.to_dict()}


def _process_node(ironic, node, node_info, cached_node):
    hooks = plugins_base.processing_hooks_manager()

    ports = {}
    for mac in (node_info.get('macs') or ()):
        try:
            port = ironic.port.create(node_uuid=node.uuid, address=mac)
            ports[mac] = port
        except exceptions.Conflict:
            LOG.warning('MAC %(mac)s appeared in discovery data for '
                        'node %(node)s, but already exists in '
                        'database - skipping',
                        {'mac': mac, 'node': node.uuid})

    node_patches = []
    port_patches = {}
    for hook_ext in hooks:
        hook_patch = hook_ext.obj.post_discover(node, list(ports.values()),
                                                node_info)
        if not hook_patch:
            continue

        node_patches.extend(hook_patch[0])
        port_patches.update(hook_patch[1])
    node_patches = [p for p in node_patches if p]
    port_patches = {mac: patch for (mac, patch) in port_patches.items()
                    if mac in ports and patch}

    node = ironic.node.update(node.uuid, node_patches)

    for mac, patches in port_patches.items():
        ironic.port.update(ports[mac].uuid, patches)

    LOG.info('Node %s was updated with data from discovery process', node.uuid)

    firewall.update_filters(ironic)

    if conf.getboolean('discoverd', 'power_off_after_discovery'):
        LOG.info('Forcing power off of node %s', node.uuid)
        try:
            ironic.node.set_power_state(node.uuid, 'off')
        except Exception as exc:
            LOG.error('Failed to power off node %s, check it\'s power '
                      'management configuration:\n%s', node.uuid, exc)
            raise utils.DiscoveryFailed('Failed to power off node %s' %
                                        node.uuid)

    eventlet.greenthread.spawn_n(_wait_for_power_off, ironic, cached_node)
    return node


_POWER_OFF_CHECK_PERIOD = 5


def _wait_for_power_off(ironic, cached_node):
    deadline = cached_node.started_at + conf.getint('discoverd', 'timeout')
    # NOTE(dtantsur): even VM's don't power off instantly, sleep first
    while time.time() < deadline:
        eventlet.greenthread.sleep(_POWER_OFF_CHECK_PERIOD)
        node = ironic.node.get(cached_node.uuid)
        if (node.power_state or 'power off').lower() == 'power off':
            patch = [{'op': 'add', 'path': '/extra/newly_discovered',
                      'value': 'true'},
                     {'op': 'remove', 'path': '/extra/on_discovery'}]
            ironic.node.update(cached_node.uuid, patch)
            return

    LOG.error('Timeout waiting for power off state of node %s after discovery',
              cached_node.uuid)


def discover(uuids):
    """Initiate discovery for given node uuids."""
    if not uuids:
        raise utils.DiscoveryFailed("No nodes to discover")

    ironic = utils.get_client()
    LOG.debug('Validating nodes %s', uuids)
    nodes = []
    for uuid in uuids:
        try:
            node = ironic.node.get(uuid)
        except exceptions.NotFound:
            LOG.error('Node %s cannot be found', uuid)
            raise utils.DiscoveryFailed("Cannot find node %s" % uuid, code=404)
        except exceptions.HttpError as exc:
            LOG.exception('Cannot get node %s', uuid)
            raise utils.DiscoveryFailed("Cannot get node %s: %s" % (uuid, exc))

        _validate(ironic, node)

        if node.extra.get('on_discovery'):
            LOG.warning('Node %s seems to be on discovery already', node.uuid)

        nodes.append(node)

    LOG.info('Proceeding with discovery on nodes %s', [n.uuid for n in nodes])
    eventlet.greenthread.spawn_n(_background_discover, ironic, nodes)


def _validate(ironic, node):
    if node.instance_uuid:
        LOG.error('Refusing to discover node %s with assigned instance_uuid',
                  node.uuid)
        raise utils.DiscoveryFailed(
            'Refusing to discover node %s with assigned instance uuid' %
            node.uuid)

    power_state = node.power_state
    if (not node.maintenance and power_state is not None
            and power_state.lower() != 'power off'):
        LOG.error('Refusing to discover node %s with power_state "%s" '
                  'and maintenance mode off',
                  node.uuid, power_state)
        raise utils.DiscoveryFailed(
            'Refusing to discover node %s with power state "%s" and '
            'maintenance mode off' %
            (node.uuid, power_state))

    validation = ironic.node.validate(node.uuid)
    if not validation.power['result']:
        LOG.error('Failed validation of power interface for node %s, '
                  'reason: %s', node.uuid, validation.power['reason'])
        raise utils.DiscoveryFailed('Failed validation of power interface for '
                                    'node %s' % node.uuid)


def _background_discover(ironic, nodes):
    patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'},
             {'op': 'add', 'path': '/extra/discovery_timestamp',
              'value': str(time.time())}]
    for node in nodes:
        node_patch = []
        if not node.maintenance:
            LOG.warning('Node %s will be put in maintenance mode', node.uuid)
            node_patch.append(
                {'op': 'replace', 'path': '/maintenance', 'value': 'true'})

        ironic.node.update(node.uuid, patch + node_patch)

    all_macs = set()
    for node in nodes:
        # TODO(dtantsur): pagination
        macs = [p.address for p in ironic.node.list_ports(node.uuid, limit=0)]
        all_macs.update(macs)
        node_cache.add_node(node.uuid,
                            bmc_address=node.driver_info.get('ipmi_address'),
                            mac=macs)

    if all_macs:
        LOG.info('Whitelisting MAC\'s %s in the firewall', all_macs)
        firewall.update_filters(ironic)

    for node in nodes:
        try:
            ironic.node.set_power_state(node.uuid, 'reboot')
        except Exception as exc:
            LOG.error('Failed to power on node %s, check it\'s power '
                      'management configuration:\n%s', node.uuid, exc)
