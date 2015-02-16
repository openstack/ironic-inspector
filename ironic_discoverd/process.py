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

"""Handling introspection data from the ramdisk."""

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

_CREDENTIALS_WAIT_RETRIES = 10
_CREDENTIALS_WAIT_PERIOD = 3
_POWER_OFF_CHECK_PERIOD = 5


def process(node_info):
    """Process data from the discovery ramdisk.

    This function heavily relies on the hooks to do the actual data processing.
    """
    hooks = plugins_base.processing_hooks_manager()
    for hook_ext in hooks:
        hook_ext.obj.before_processing(node_info)

    cached_node = node_cache.find_node(
        bmc_address=node_info.get('ipmi_address'),
        mac=node_info.get('macs'))

    ironic = utils.get_client()
    try:
        node = ironic.node.get(cached_node.uuid)
    except exceptions.NotFound:
        msg = ('Node UUID %s was found in cache, but is not found in Ironic'
               % cached_node.uuid)
        cached_node.finished(error=msg)
        raise utils.Error(msg, code=404)

    try:
        return _process_node(ironic, node, node_info, cached_node)
    except utils.Error as exc:
        cached_node.finished(error=str(exc))
        raise
    except Exception as exc:
        msg = 'Unexpected exception during processing'
        LOG.exception(msg)
        cached_node.finished(error=msg)
        raise utils.Error(msg)


def _run_post_hooks(node, ports, node_info):
    hooks = plugins_base.processing_hooks_manager()
    port_instances = list(ports.values())

    node_patches = []
    port_patches = {}
    for hook_ext in hooks:
        hook_patch = hook_ext.obj.before_update(node, port_instances,
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
            LOG.warning('MAC %(mac)s appeared in introspection data for '
                        'node %(node)s, but already exists in '
                        'database - skipping',
                        {'mac': mac, 'node': node.uuid})

    node_patches, port_patches = _run_post_hooks(node, ports, node_info)
    node = utils.retry_on_conflict(ironic.node.update, node.uuid, node_patches)
    for mac, patches in port_patches.items():
        utils.retry_on_conflict(ironic.port.update, ports[mac].uuid, patches)

    LOG.debug('Node %s was updated with data from introspection process, '
              'patches %s, port patches %s',
              node.uuid, node_patches, port_patches)

    firewall.update_filters(ironic)

    if cached_node.options.get('new_ipmi_credentials'):
        new_username, new_password = (
            cached_node.options.get('new_ipmi_credentials'))
        eventlet.greenthread.spawn_n(_finish_set_ipmi_credentials,
                                     ironic, cached_node,
                                     new_username, new_password)
        return {'ipmi_setup_credentials': True,
                'ipmi_username': new_username,
                'ipmi_password': new_password}
    else:
        eventlet.greenthread.spawn_n(_finish, ironic, cached_node)
        return {}


def _finish_set_ipmi_credentials(ironic, cached_node,
                                 new_username, new_password):
    patch = [{'op': 'add', 'path': '/driver_info/ipmi_username',
              'value': new_username},
             {'op': 'add', 'path': '/driver_info/ipmi_password',
              'value': new_password}]
    utils.retry_on_conflict(ironic.node.update, cached_node.uuid, patch)

    for attempt in range(_CREDENTIALS_WAIT_RETRIES):
        try:
            # We use this call because it requires valid credentials.
            # We don't care about boot device, obviously.
            ironic.node.get_boot_device(cached_node.uuid)
        except Exception as exc:
            LOG.info('Waiting for credentials update on node %s, attempt %d'
                     'current error is %s',
                     cached_node.uuid, attempt, exc)
            eventlet.greenthread.sleep(_CREDENTIALS_WAIT_PERIOD)
        else:
            _finish(ironic, cached_node)
            return

    msg = ('Failed to validate updated IPMI credentials for node '
           '%s, node might require maintenance' % cached_node.uuid)
    cached_node.finished(error=msg)
    raise utils.Error(msg)


def _force_power_off(ironic, cached_node):
    LOG.debug('Forcing power off of node %s', cached_node.uuid)
    try:
        utils.retry_on_conflict(ironic.node.set_power_state,
                                cached_node.uuid, 'off')
    except Exception as exc:
        msg = ('Failed to power off node %s, check it\'s power '
               'management configuration: %s' % (cached_node.uuid, exc))
        cached_node.finished(error=msg)
        raise utils.Error(msg)

    deadline = cached_node.started_at + conf.getint('discoverd', 'timeout')
    while time.time() < deadline:
        node = ironic.node.get(cached_node.uuid)
        if (node.power_state or '').lower() == 'power off':
            return
        LOG.info('Waiting for node %s to power off, current state is %s',
                 cached_node.uuid, node.power_state)
        eventlet.greenthread.sleep(_POWER_OFF_CHECK_PERIOD)

    msg = ('Timeout waiting for node %s to power off after introspection' %
           cached_node.uuid)
    cached_node.finished(error=msg)
    raise utils.Error(msg)


def _finish(ironic, cached_node):
    _force_power_off(ironic, cached_node)

    patch = [{'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
             {'op': 'remove', 'path': '/extra/on_discovery'}]
    utils.retry_on_conflict(ironic.node.update, cached_node.uuid, patch)

    cached_node.finished()
    LOG.info('Introspection finished successfully for node %s',
             cached_node.uuid)
