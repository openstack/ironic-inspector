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
from oslo_config import cfg

from ironic_inspector.common.i18n import _, _LE, _LI
from ironic_inspector.common import ironic as ir_utils
from ironic_inspector.common import swift
from ironic_inspector import firewall
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector import rules
from ironic_inspector import utils

CONF = cfg.CONF

LOG = utils.getProcessingLogger(__name__)

_CREDENTIALS_WAIT_RETRIES = 10
_CREDENTIALS_WAIT_PERIOD = 3
_STORAGE_EXCLUDED_KEYS = {'logs'}


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
                      {'hook': hook_ext.name, 'error': exc},
                      data=introspection_data)
            failures.append('Preprocessing hook %(hook)s: %(error)s' %
                            {'hook': hook_ext.name, 'error': exc})
        except Exception as exc:
            LOG.exception(_LE('Hook %(hook)s failed, delaying error report '
                              'until node look up: %(error)s'),
                          {'hook': hook_ext.name, 'error': exc},
                          data=introspection_data)
            failures.append(_('Unexpected exception %(exc_class)s during '
                              'preprocessing in hook %(hook)s: %(error)s') %
                            {'hook': hook_ext.name,
                             'exc_class': exc.__class__.__name__,
                             'error': exc})

    node_info = _find_node_info(introspection_data, failures)
    if node_info:
        # Locking is already done in find_node() but may be not done in a
        # node_not_found hook
        node_info.acquire_lock()

    if failures or node_info is None:
        msg = _('The following failures happened during running '
                'pre-processing hooks:\n%s') % '\n'.join(failures)
        if node_info is not None:
            node_info.finished(error='\n'.join(failures))
        raise utils.Error(msg, node_info=node_info, data=introspection_data)

    LOG.info(_LI('Matching node is %s'), node_info.uuid,
             node_info=node_info, data=introspection_data)

    if node_info.finished_at is not None:
        # race condition or introspection canceled
        raise utils.Error(_('Node processing already finished with '
                            'error: %s') % node_info.error,
                          node_info=node_info, code=400)

    try:
        node = node_info.node()
    except exceptions.NotFound:
        msg = _('Node was found in cache, but is not found in Ironic')
        node_info.finished(error=msg)
        raise utils.Error(msg, code=404, node_info=node_info,
                          data=introspection_data)

    try:
        return _process_node(node, introspection_data, node_info)
    except utils.Error as exc:
        node_info.finished(error=str(exc))
        raise
    except Exception as exc:
        LOG.exception(_LE('Unexpected exception during processing'))
        msg = _('Unexpected exception %(exc_class)s during processing: '
                '%(error)s') % {'exc_class': exc.__class__.__name__,
                                'error': exc}
        node_info.finished(error=msg)
        raise utils.Error(msg, node_info=node_info, data=introspection_data)


def _run_post_hooks(node_info, introspection_data):
    hooks = plugins_base.processing_hooks_manager()

    for hook_ext in hooks:
        hook_ext.obj.before_update(introspection_data, node_info)


def _process_node(node, introspection_data, node_info):
    # NOTE(dtantsur): repeat the check in case something changed
    ir_utils.check_provision_state(node)

    node_info.create_ports(introspection_data.get('macs') or ())

    _run_post_hooks(node_info, introspection_data)

    if CONF.processing.store_data == 'swift':
        stored_data = {k: v for k, v in introspection_data.items()
                       if k not in _STORAGE_EXCLUDED_KEYS}
        swift_object_name = swift.store_introspection_data(stored_data,
                                                           node_info.uuid)
        LOG.info(_LI('Introspection data was stored in Swift in object %s'),
                 swift_object_name,
                 node_info=node_info, data=introspection_data)
        if CONF.processing.store_data_location:
            node_info.patch([{'op': 'add', 'path': '/extra/%s' %
                              CONF.processing.store_data_location,
                              'value': swift_object_name}])
    else:
        LOG.debug('Swift support is disabled, introspection data '
                  'won\'t be stored',
                  node_info=node_info, data=introspection_data)

    ironic = ir_utils.get_client()
    firewall.update_filters(ironic)

    node_info.invalidate_cache()
    rules.apply(node_info, introspection_data)

    resp = {'uuid': node.uuid}

    if node_info.options.get('new_ipmi_credentials'):
        new_username, new_password = (
            node_info.options.get('new_ipmi_credentials'))
        utils.executor().submit(_finish_set_ipmi_credentials,
                                ironic, node, node_info, introspection_data,
                                new_username, new_password)
        resp['ipmi_setup_credentials'] = True
        resp['ipmi_username'] = new_username
        resp['ipmi_password'] = new_password
    else:
        utils.executor().submit(_finish, ironic, node_info, introspection_data)

    return resp


def _finish_set_ipmi_credentials(ironic, node, node_info, introspection_data,
                                 new_username, new_password):
    patch = [{'op': 'add', 'path': '/driver_info/ipmi_username',
              'value': new_username},
             {'op': 'add', 'path': '/driver_info/ipmi_password',
              'value': new_password}]
    if (not ir_utils.get_ipmi_address(node) and
            introspection_data.get('ipmi_address')):
        patch.append({'op': 'add', 'path': '/driver_info/ipmi_address',
                      'value': introspection_data['ipmi_address']})
    node_info.patch(patch)

    for attempt in range(_CREDENTIALS_WAIT_RETRIES):
        try:
            # We use this call because it requires valid credentials.
            # We don't care about boot device, obviously.
            ironic.node.get_boot_device(node_info.uuid)
        except Exception as exc:
            LOG.info(_LI('Waiting for credentials update, attempt %(attempt)d '
                         'current error is %(exc)s') %
                     {'attempt': attempt, 'exc': exc},
                     node_info=node_info, data=introspection_data)
            eventlet.greenthread.sleep(_CREDENTIALS_WAIT_PERIOD)
        else:
            _finish(ironic, node_info, introspection_data)
            return

    msg = (_('Failed to validate updated IPMI credentials for node '
             '%s, node might require maintenance') % node_info.uuid)
    node_info.finished(error=msg)
    raise utils.Error(msg, node_info=node_info, data=introspection_data)


def _finish(ironic, node_info, introspection_data):
    LOG.debug('Forcing power off of node %s', node_info.uuid)
    try:
        ironic.node.set_power_state(node_info.uuid, 'off')
    except Exception as exc:
        if node_info.node().provision_state == 'enroll':
            LOG.info(_LI("Failed to power off the node in 'enroll' state, "
                         "ignoring; error was %s") % exc,
                     node_info=node_info, data=introspection_data)
        else:
            msg = (_('Failed to power off node %(node)s, check it\'s '
                     'power management configuration: %(exc)s') %
                   {'node': node_info.uuid, 'exc': exc})
            node_info.finished(error=msg)
            raise utils.Error(msg, node_info=node_info,
                              data=introspection_data)

    node_info.finished()
    LOG.info(_LI('Introspection finished successfully'),
             node_info=node_info, data=introspection_data)
