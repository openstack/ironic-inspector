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

_POWER_OFF_CHECK_PERIOD = 5


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

    updated = _process_node(ironic, node, node_info, cached_node)
    return {'node': updated.to_dict()}


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


def _wait_for_power_off(ironic, cached_node):
    deadline = cached_node.started_at + conf.getint('discoverd', 'timeout')
    # NOTE(dtantsur): even VM's don't power off instantly, sleep first
    while time.time() < deadline:
        eventlet.greenthread.sleep(_POWER_OFF_CHECK_PERIOD)
        node = ironic.node.get(cached_node.uuid)
        if (node.power_state or 'power off').lower() == 'power off':
            _finish_discovery(ironic, node)
            return

    LOG.error('Timeout waiting for power off state of node %s after discovery',
              cached_node.uuid)


def _finish_discovery(ironic, node):
    patch = [{'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
             {'op': 'remove', 'path': '/extra/on_discovery'}]
    ironic.node.update(node.uuid, patch)
