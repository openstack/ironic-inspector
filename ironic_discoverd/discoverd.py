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

    if node_info.get('error'):
        LOG.error('Error happened during discovery: %s',
                  node_info['error'])
        raise utils.DiscoveryFailed(node_info['error'])

    bmc_address = node_info.get('ipmi_address')

    compat = conf.getboolean('discoverd', 'ports_for_inactive_interfaces')
    if 'interfaces' not in node_info and 'macs' in node_info:
        LOG.warning('Using "macs" field is deprecated, please '
                    'update your discovery ramdisk')
        node_info['interfaces'] = {'dummy%d' % i: {'mac': m}
                                   for i, m in enumerate(node_info['macs'])}
        compat = True

    valid_interfaces = {
        n: iface for n, iface in node_info['interfaces'].items()
        if utils.is_valid_mac(iface['mac']) and (compat or iface.get('ip'))
    }
    valid_macs = [iface['mac'] for iface in valid_interfaces.values()]
    if valid_interfaces != node_info['interfaces']:
        LOG.warning(
            'The following interfaces were invalid or not eligible in '
            'discovery data for node with BMC %(ipmi_address)s and were '
            'excluded: %(invalid)s',
            {'invalid': {n: iface
                         for n, iface in node_info['interfaces'].items()
                         if n not in valid_interfaces},
             'ipmi_address': bmc_address})
        LOG.info('Eligible interfaces are %s', valid_interfaces)

    node_info['interfaces'] = valid_interfaces
    node_info['macs'] = valid_macs

    cached_node = node_cache.pop_node(bmc_address=bmc_address, mac=valid_macs)
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

    updated = _process_node(ironic, node, node_info)
    return {'node': updated.to_dict()}


def _process_node(ironic, node, node_info):
    hooks = plugins_base.processing_hooks_manager()

    ports = {}
    for mac in node_info['macs']:
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

    ironic.node.update(node.uuid, node_patches)

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

    patch = [{'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
             {'op': 'remove', 'path': '/extra/on_discovery'}]
    return ironic.node.update(node.uuid, patch)


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
