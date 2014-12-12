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

"""Handling discovery data from the ramdisk."""

import logging
import time

import eventlet
from ironicclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd.plugins import base as plugins_base
from ironic_discoverd import utils


LOG = logging.getLogger("ironic_discoverd.process")

_POWER_CHECK_PERIOD = 5


def process(node_info):
    """Process data from discovery ramdisk.

    This function heavily relies on the hooks to do the actual data processing.
    """
    hooks = plugins_base.processing_hooks_manager()
    for hook_ext in hooks:
        hook_ext.obj.pre_discover(node_info)

    cached_node = node_cache.pop_node(
        bmc_address=node_info.get('ipmi_address'),
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

    return _process_node(ironic, node, node_info, cached_node)


def _run_post_hooks(node, ports, node_info):
    hooks = plugins_base.processing_hooks_manager()
    port_instances = list(ports.values())

    node_patches = []
    port_patches = {}
    for hook_ext in hooks:
        hook_patch = hook_ext.obj.post_discover(node, port_instances,
                                                node_info)
        if not hook_patch:
            continue

        node_patches.extend(hook_patch[0])
        port_patches.update(hook_patch[1])

    node_patches = [p for p in node_patches if p]
    port_patches = {mac: patch for (mac, patch) in port_patches.items()
                    if mac in ports and patch}
    return node_patches, port_patches


def _process_node(ironic, node, node_info, cached_node):
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

    node_patches, port_patches = _run_post_hooks(node, ports, node_info)
    node = utils.retry_on_conflict(ironic.node.update, node.uuid, node_patches)
    for mac, patches in port_patches.items():
        utils.retry_on_conflict(ironic.port.update, ports[mac].uuid, patches)

    LOG.debug('Node %s was updated with data from discovery process, '
              'patches %s, port patches %s',
              node.uuid, node_patches, port_patches)

    firewall.update_filters(ironic)

    if node.extra.get('ipmi_setup_credentials'):
        eventlet.greenthread.spawn_n(_wait_for_power_management,
                                     ironic, cached_node)
        return {'ipmi_setup_credentials': True,
                'ipmi_username': node.driver_info.get('ipmi_username'),
                'ipmi_password': node.driver_info.get('ipmi_password')}
    else:
        _finish_discovery(ironic, cached_node)
        return {}


def _wait_for_power_management(ironic, cached_node):
    deadline = cached_node.started_at + conf.getint('discoverd', 'timeout')
    while time.time() < deadline:
        eventlet.greenthread.sleep(_POWER_CHECK_PERIOD)
        validation = utils.retry_on_conflict(ironic.node.validate,
                                             cached_node.uuid)
        if validation.power['result']:
            _finish_discovery(ironic, cached_node)
            return
        LOG.debug('Waiting for management credentials on node %s '
                  'to be updated, current error: %s',
                  cached_node.uuid, validation.power['reason'])

    LOG.error('Timeout waiting for power credentials update of node %s '
              'after discovery', cached_node.uuid)


def _force_power_off(ironic, node):
    LOG.debug('Forcing power off of node %s', node.uuid)
    try:
        utils.retry_on_conflict(ironic.node.set_power_state, node.uuid, 'off')
    except Exception as exc:
        LOG.error('Failed to power off node %s, check it\'s power '
                  'management configuration:\n%s', node.uuid, exc)
        raise utils.DiscoveryFailed('Failed to power off node %s' % node.uuid)


def _finish_discovery(ironic, node):
    _force_power_off(ironic, node)

    patch = [{'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
             {'op': 'remove', 'path': '/extra/on_discovery'}]
    utils.retry_on_conflict(ironic.node.update, node.uuid, patch)

    LOG.info('Discovery finished successfully for node %s', node.uuid)
