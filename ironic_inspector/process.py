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

import eventlet
from ironicclient import exceptions
from oslo_log import log

from ironic_inspector.common.i18n import _, _LE, _LI
from ironic_inspector import firewall
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector import utils


LOG = log.getLogger("ironic_inspector.process")

_CREDENTIALS_WAIT_RETRIES = 10
_CREDENTIALS_WAIT_PERIOD = 3


def _find_node_info(introspection_data, failures):
    try:
        return node_cache.find_node(
            bmc_address=introspection_data.get('ipmi_address'),
            mac=introspection_data.get('macs'))
    except utils.NotFoundInCacheError as exc:
        not_found_hook = plugins_base.node_not_found_hook_manager()
        if not_found_hook is None:
            failures.append(_('Look up error: %s') % exc)
            return
        # NOTE(sambetts): If not_found_hook is not none it means that we were
        # unable to find the node in the node cache and there is a node not
        # found hook defined so we should try to send the introspection data
        # to that hook to generate the node info before bubbling up the error.
        try:
            node_info = not_found_hook.driver(introspection_data)
            if node_info:
                return node_info
            failures.append(_("Node not found hook returned nothing"))
        except Exception as exc:
            failures.append(_("Node not found hook failed: %s") % exc)
    except utils.Error as exc:
        failures.append(_('Look up error: %s') % exc)


def process(introspection_data):
    """Process data from the ramdisk.

    This function heavily relies on the hooks to do the actual data processing.
    """
    hooks = plugins_base.processing_hooks_manager()
    failures = []
    for hook_ext in hooks:
        # NOTE(dtantsur): catch exceptions, so that we have changes to update
        # node introspection status after look up
        try:
            hook_ext.obj.before_processing(introspection_data)
        except utils.Error as exc:
            LOG.error(_LE('Hook %(hook)s failed, delaying error report '
                          'until node look up: %(error)s'),
                      {'hook': hook_ext.name, 'error': exc})
            failures.append('Preprocessing hook %(hook)s: %(error)s' %
                            {'hook': hook_ext.name, 'error': exc})
        except Exception as exc:
            LOG.exception(_LE('Hook %(hook)s failed, delaying error report '
                              'until node look up: %(error)s'),
                          {'hook': hook_ext.name, 'error': exc})
            failures.append(_('Unexpected exception during preprocessing '
                              'in hook %s') % hook_ext.name)

    node_info = _find_node_info(introspection_data, failures)

    if failures and node_info:
        msg = _('The following failures happened during running '
                'pre-processing hooks for node %(uuid)s:\n%(failures)s') % {
            'uuid': node_info.uuid,
            'failures': '\n'.join(failures)
        }
        node_info.finished(error=_('Data pre-processing failed'))
        raise utils.Error(msg)
    elif not node_info:
        msg = _('The following failures happened during running '
                'pre-processing hooks for unknown node:\n%(failures)s') % {
            'failures': '\n'.join(failures)
        }
        raise utils.Error(msg)

    ironic = utils.get_client()
    try:
        node = node_info.node(ironic)
    except exceptions.NotFound:
        msg = (_('Node UUID %s was found in cache, but is not found in Ironic')
               % node_info.uuid)
        node_info.finished(error=msg)
        raise utils.Error(msg, code=404)

    try:
        return _process_node(ironic, node, introspection_data, node_info)
    except utils.Error as exc:
        node_info.finished(error=str(exc))
        raise
    except Exception as exc:
        msg = _('Unexpected exception during processing')
        LOG.exception(msg)
        node_info.finished(error=msg)
        raise utils.Error(msg)


def _run_post_hooks(node_info, introspection_data):
    hooks = plugins_base.processing_hooks_manager()

    node_patches = []
    port_patches = {}
    for hook_ext in hooks:
        hook_ext.obj.before_update(introspection_data, node_info,
                                   node_patches, port_patches)

    node_patches = [p for p in node_patches if p]
    port_patches = {mac: patch for (mac, patch) in port_patches.items()
                    if patch and mac in node_info.ports()}
    return node_patches, port_patches


def _process_node(ironic, node, introspection_data, node_info):
    # NOTE(dtantsur): repeat the check in case something changed
    utils.check_provision_state(node)

    node_info.create_ports(introspection_data.get('macs') or (), ironic=ironic)

    node_patches, port_patches = _run_post_hooks(node_info,
                                                 introspection_data)

    node = ironic.node.update(node.uuid, node_patches)
    for mac, patches in port_patches.items():
        port = node_info.ports(ironic)[mac]
        ironic.port.update(port.uuid, patches)

    LOG.debug('Node %s was updated with data from introspection process, '
              'patches %s, port patches %s',
              node.uuid, node_patches, port_patches)

    firewall.update_filters(ironic)

    resp = {'uuid': node.uuid}

    if node_info.options.get('new_ipmi_credentials'):
        new_username, new_password = (
            node_info.options.get('new_ipmi_credentials'))
        utils.spawn_n(_finish_set_ipmi_credentials,
                      ironic, node, node_info, introspection_data,
                      new_username, new_password)
        resp['ipmi_setup_credentials'] = True
        resp['ipmi_username'] = new_username
        resp['ipmi_password'] = new_password
    else:
        utils.spawn_n(_finish, ironic, node_info)

    return resp


def _finish_set_ipmi_credentials(ironic, node, node_info, introspection_data,
                                 new_username, new_password):
    patch = [{'op': 'add', 'path': '/driver_info/ipmi_username',
              'value': new_username},
             {'op': 'add', 'path': '/driver_info/ipmi_password',
              'value': new_password}]
    if (not utils.get_ipmi_address(node) and
            introspection_data.get('ipmi_address')):
        patch.append({'op': 'add', 'path': '/driver_info/ipmi_address',
                      'value': introspection_data['ipmi_address']})
    ironic.node.update(node_info.uuid, patch)

    for attempt in range(_CREDENTIALS_WAIT_RETRIES):
        try:
            # We use this call because it requires valid credentials.
            # We don't care about boot device, obviously.
            ironic.node.get_boot_device(node_info.uuid)
        except Exception as exc:
            LOG.info(_LI('Waiting for credentials update on node %(node)s,'
                         ' attempt %(attempt)d current error is %(exc)s') %
                     {'node': node_info.uuid,
                      'attempt': attempt, 'exc': exc})
            eventlet.greenthread.sleep(_CREDENTIALS_WAIT_PERIOD)
        else:
            _finish(ironic, node_info)
            return

    msg = (_('Failed to validate updated IPMI credentials for node '
             '%s, node might require maintenance') % node_info.uuid)
    node_info.finished(error=msg)
    raise utils.Error(msg)


def _finish(ironic, node_info):
    LOG.debug('Forcing power off of node %s', node_info.uuid)
    try:
        ironic.node.set_power_state(node_info.uuid, 'off')
    except Exception as exc:
        msg = (_('Failed to power off node %(node)s, check it\'s power '
                 'management configuration: %(exc)s') %
               {'node': node_info.uuid, 'exc': exc})
        node_info.finished(error=msg)
        raise utils.Error(msg)

    node_info.finished()
    LOG.info(_LI('Introspection finished successfully for node %s'),
             node_info.uuid)
