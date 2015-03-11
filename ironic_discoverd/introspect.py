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

import logging
import string

import eventlet
from ironicclient import exceptions
from oslo_config import cfg

from ironic_discoverd.common.i18n import _, _LI, _LW
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd import utils

CONF = cfg.CONF


LOG = logging.getLogger("ironic_discoverd.introspect")
# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'manageable', 'inspecting'}
PASSWORD_ACCEPTED_CHARS = set(string.ascii_letters + string.digits)
PASSWORD_MAX_LENGTH = 20  # IPMI v2.0


def _validate_ipmi_credentials(node, new_ipmi_credentials):
    if not CONF.discoverd.enable_setting_ipmi_credentials:
        raise utils.Error(
            _('IPMI credentials setup is disabled in configuration'))

    if not node.maintenance:
        # Otherwise Ironic is going to interfere
        raise utils.Error(_('Node should be in maintenance mode to set '
                            'IPMI credentials on it'))

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


def introspect(uuid, new_ipmi_credentials=None):
    """Initiate hardware properties introspection for a given node.

    :param uuid: node uuid
    :param new_ipmi_credentials: tuple (new username, new password) or None
    :raises: Error
    """
    ironic = utils.get_client()

    try:
        node = ironic.node.get(uuid)
    except exceptions.NotFound:
        raise utils.Error(_("Cannot find node %s") % uuid, code=404)
    except exceptions.HttpError as exc:
        raise utils.Error(_("Cannot get node %(node)s: %(exc)s") %
                          {'node': uuid, 'exc': exc})

    if not node.maintenance:
        provision_state = node.provision_state
        if provision_state and provision_state.lower() not in VALID_STATES:
            msg = _('Refusing to introspect node %(node)s with provision state'
                    ' "%(state)s" and maintenance mode off')
            raise utils.Error(msg % {'node': node.uuid,
                                     'state': provision_state})
    else:
        LOG.info(_LI('Node %s is in maintenance mode, skipping'
                     ' provision states check'), node.uuid)

    if new_ipmi_credentials:
        new_ipmi_credentials = (
            _validate_ipmi_credentials(node, new_ipmi_credentials))
    else:
        validation = utils.retry_on_conflict(ironic.node.validate, node.uuid)
        if not validation.power['result']:
            msg = _('Failed validation of power interface for node %(node)s, '
                    'reason: %(reason)s')
            raise utils.Error(msg % {'node': node.uuid,
                                     'reason': validation.power['reason']})

    cached_node = node_cache.add_node(node.uuid,
                                      bmc_address=utils.get_ipmi_address(node))
    cached_node.set_option('new_ipmi_credentials', new_ipmi_credentials)

    def _handle_exceptions():
        try:
            _background_introspect(ironic, cached_node)
        except utils.Error as exc:
            cached_node.finished(error=str(exc))
        except Exception as exc:
            msg = _('Unexpected exception in background introspection thread')
            LOG.exception(msg)
            cached_node.finished(error=msg)

    eventlet.greenthread.spawn_n(_handle_exceptions)


def _background_introspect(ironic, cached_node):
    patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'}]
    utils.retry_on_conflict(ironic.node.update, cached_node.uuid, patch)

    # TODO(dtantsur): pagination
    macs = [p.address for p in ironic.node.list_ports(cached_node.uuid,
                                                      limit=0)]
    if macs:
        cached_node.add_attribute(node_cache.MACS_ATTRIBUTE, macs)
        LOG.info(_LI('Whitelisting MAC\'s %(macs)s for node %(node)s on the'
                     ' firewall') %
                 {'macs': macs, 'node': cached_node.uuid})
        firewall.update_filters(ironic)

    if not cached_node.options.get('new_ipmi_credentials'):
        try:
            utils.retry_on_conflict(ironic.node.set_boot_device,
                                    cached_node.uuid, 'pxe', persistent=False)
        except Exception as exc:
            LOG.warning(_LW('Failed to set boot device to PXE for'
                            ' node %(node)s: %(exc)s') %
                        {'node': cached_node.uuid, 'exc': exc})

        try:
            utils.retry_on_conflict(ironic.node.set_power_state,
                                    cached_node.uuid, 'reboot')
        except Exception as exc:
            raise utils.Error(_('Failed to power on node %(node)s,'
                                ' check it\'s power '
                                'management configuration:\n%(exc)s')
                              % {'node': cached_node.uuid, 'exc': exc})
    else:
        LOG.info(_LI('Introspection environment is ready for node %(node)s, '
                 'manual power on is required within %(timeout)d seconds') %
                 {'node': cached_node.uuid,
                  'timeout': CONF.discoverd.timeout})
