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

"""Handling introspection request."""

import re
import string
import time

from eventlet import semaphore
from ironicclient import exceptions
from oslo_config import cfg
from oslo_log import log

from ironic_inspector.common.i18n import _, _LI, _LW
from ironic_inspector import firewall
from ironic_inspector import node_cache
from ironic_inspector import utils

CONF = cfg.CONF


LOG = log.getLogger("ironic_inspector.introspect")
PASSWORD_ACCEPTED_CHARS = set(string.ascii_letters + string.digits)
PASSWORD_MAX_LENGTH = 20  # IPMI v2.0

_LAST_INTROSPECTION_TIME = 0
_LAST_INTROSPECTION_LOCK = semaphore.BoundedSemaphore()


def _validate_ipmi_credentials(node, new_ipmi_credentials):
    if not CONF.processing.enable_setting_ipmi_credentials:
        raise utils.Error(
            _('IPMI credentials setup is disabled in configuration'))

    new_username, new_password = new_ipmi_credentials
    if not new_username:
        new_username = node.driver_info.get('ipmi_username')
    if not new_username:
        raise utils.Error(_('Setting IPMI credentials requested for node %s,'
                            ' but neither new user name nor'
                            ' driver_info[ipmi_username] are provided')
                          % node.uuid)
    wrong_chars = {c for c in new_password
                   if c not in PASSWORD_ACCEPTED_CHARS}
    if wrong_chars:
        raise utils.Error(_('Forbidden characters encountered in new IPMI '
                            'password for node %(node)s: "%(chars)s"; '
                            'use only letters and numbers') %
                          {'node': node.uuid, 'chars': ''.join(wrong_chars)})
    if not 0 < len(new_password) <= PASSWORD_MAX_LENGTH:
        raise utils.Error(_('IPMI password length should be > 0 and <= %d')
                          % PASSWORD_MAX_LENGTH)

    return new_username, new_password


def introspect(uuid, new_ipmi_credentials=None, token=None):
    """Initiate hardware properties introspection for a given node.

    :param uuid: node uuid
    :param new_ipmi_credentials: tuple (new username, new password) or None
    :param token: authentication token
    :raises: Error
    """
    ironic = utils.get_client(token)

    try:
        node = ironic.node.get(uuid)
    except exceptions.NotFound:
        raise utils.Error(_("Cannot find node %s") % uuid, code=404)
    except exceptions.HttpError as exc:
        raise utils.Error(_("Cannot get node %(node)s: %(exc)s") %
                          {'node': uuid, 'exc': exc})

    utils.check_provision_state(node, with_credentials=new_ipmi_credentials)

    if new_ipmi_credentials:
        new_ipmi_credentials = (
            _validate_ipmi_credentials(node, new_ipmi_credentials))
    else:
        validation = ironic.node.validate(node.uuid)
        if not validation.power['result']:
            msg = _('Failed validation of power interface for node %(node)s, '
                    'reason: %(reason)s')
            raise utils.Error(msg % {'node': node.uuid,
                                     'reason': validation.power['reason']})

    node_info = node_cache.add_node(node.uuid,
                                    bmc_address=utils.get_ipmi_address(node),
                                    ironic=ironic)
    node_info.set_option('new_ipmi_credentials', new_ipmi_credentials)

    def _handle_exceptions():
        try:
            _background_introspect(ironic, node_info)
        except utils.Error as exc:
            node_info.finished(error=str(exc))
        except Exception as exc:
            msg = _('Unexpected exception in background introspection thread')
            LOG.exception(msg)
            node_info.finished(error=msg)

    utils.spawn_n(_handle_exceptions)


def _background_introspect(ironic, node_info):
    global _LAST_INTROSPECTION_TIME

    # TODO(dtantsur): pagination
    macs = list(node_info.ports())
    if macs:
        node_info.add_attribute(node_cache.MACS_ATTRIBUTE, macs)
        LOG.info(_LI('Whitelisting MAC\'s %(macs)s for node %(node)s on the'
                     ' firewall') %
                 {'macs': macs, 'node': node_info.uuid})
        firewall.update_filters(ironic)

    attrs = node_info.attributes
    if CONF.processing.node_not_found_hook is None and not attrs:
        raise utils.Error(
            _('No lookup attributes were found for node %s, inspector won\'t '
              'be able to find it after introspection. Consider creating '
              'ironic ports or providing an IPMI address.') % node_info.uuid)

    LOG.info(_LI('The following attributes will be used for looking up '
                 'node %(uuid)s: %(attrs)s'),
             {'attrs': attrs, 'uuid': node_info.uuid})

    if not node_info.options.get('new_ipmi_credentials'):
        try:
            ironic.node.set_boot_device(node_info.uuid, 'pxe',
                                        persistent=False)
        except Exception as exc:
            LOG.warning(_LW('Failed to set boot device to PXE for'
                            ' node %(node)s: %(exc)s') %
                        {'node': node_info.uuid, 'exc': exc})

        if re.match(CONF.introspection_delay_drivers, node_info.node().driver):
            LOG.debug('Attempting to acquire lock on last introspection time')
            with _LAST_INTROSPECTION_LOCK:
                delay = (_LAST_INTROSPECTION_TIME - time.time()
                         + CONF.introspection_delay)
                if delay > 0:
                    LOG.debug('Waiting %d seconds before sending the next '
                              'node on introspection', delay)
                    time.sleep(delay)
                _LAST_INTROSPECTION_TIME = time.time()

        try:
            ironic.node.set_power_state(node_info.uuid, 'reboot')
        except Exception as exc:
            raise utils.Error(_('Failed to power on node %(node)s,'
                                ' check it\'s power '
                                'management configuration:\n%(exc)s')
                              % {'node': node_info.uuid, 'exc': exc})
        LOG.info(_LI('Introspection started successfully for node %s'),
                 node_info.uuid)
    else:
        LOG.info(_LI('Introspection environment is ready for node %(node)s, '
                 'manual power on is required within %(timeout)d seconds') %
                 {'node': node_info.uuid,
                  'timeout': CONF.timeout})
