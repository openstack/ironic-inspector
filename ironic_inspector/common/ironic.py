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

import socket

from ironicclient import client
from ironicclient import exceptions as ironic_exc
import netaddr
from oslo_config import cfg

from ironic_inspector.common.i18n import _, _LW
from ironic_inspector.common import keystone
from ironic_inspector import utils

CONF = cfg.CONF
LOG = utils.getProcessingLogger(__name__)

# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'manageable', 'inspecting', 'inspectfail'}
SET_CREDENTIALS_VALID_STATES = {'enroll'}

# 1.11 is API version, which support 'enroll' state
DEFAULT_IRONIC_API_VERSION = '1.11'

IRONIC_GROUP = 'ironic'

IRONIC_OPTS = [
    cfg.StrOpt('os_region',
               help=_('Keystone region used to get Ironic endpoints.')),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help=_('Method to use for authentication: noauth or '
                      'keystone.')),
    cfg.StrOpt('ironic_url',
               default='http://localhost:6385/',
               help=_('Ironic API URL, used to set Ironic API URL when '
                      'auth_strategy option is noauth to work with standalone '
                      'Ironic without keystone.')),
    cfg.StrOpt('os_service_type',
               default='baremetal',
               help=_('Ironic service type.')),
    cfg.StrOpt('os_endpoint_type',
               default='internalURL',
               help=_('Ironic endpoint type.')),
    cfg.IntOpt('retry_interval',
               default=2,
               help=_('Interval between retries in case of conflict error '
                      '(HTTP 409).')),
    cfg.IntOpt('max_retries',
               default=30,
               help=_('Maximum number of retries in case of conflict error '
                      '(HTTP 409).')),
]


CONF.register_opts(IRONIC_OPTS, group=IRONIC_GROUP)
keystone.register_auth_opts(IRONIC_GROUP)

IRONIC_SESSION = None


class NotFound(utils.Error):
    """Node not found in Ironic."""

    def __init__(self, node_ident, code=404, *args, **kwargs):
        msg = _('Node %s was not found in Ironic') % node_ident
        super(NotFound, self).__init__(msg, code, *args, **kwargs)


def reset_ironic_session():
    """Reset the global session variable.

    Mostly useful for unit tests.
    """
    global IRONIC_SESSION
    IRONIC_SESSION = None


def get_ipmi_address(node):
    ipmi_fields = ['ipmi_address'] + CONF.ipmi_address_fields
    # NOTE(sambetts): IPMI Address is useless to us if bridging is enabled so
    # just ignore it and return None
    if node.driver_info.get("ipmi_bridging", "no") != "no":
        return
    for name in ipmi_fields:
        value = node.driver_info.get(name)
        if not value:
            continue

        try:
            ip = socket.gethostbyname(value)
        except socket.gaierror:
            msg = _('Failed to resolve the hostname (%(value)s)'
                    ' for node %(uuid)s')
            raise utils.Error(msg % {'value': value,
                                     'uuid': node.uuid},
                              node_info=node)

        if netaddr.IPAddress(ip).is_loopback():
            LOG.warning(_LW('Ignoring loopback BMC address %s'), ip,
                        node_info=node)
            ip = None

        return ip


def get_client(token=None,
               api_version=DEFAULT_IRONIC_API_VERSION):  # pragma: no cover
    """Get Ironic client instance."""
    # NOTE: To support standalone ironic without keystone
    if CONF.ironic.auth_strategy == 'noauth':
        args = {'token': 'noauth',
                'endpoint': CONF.ironic.ironic_url}
    else:
        global IRONIC_SESSION
        if not IRONIC_SESSION:
            IRONIC_SESSION = keystone.get_session(IRONIC_GROUP)
        if token is None:
            args = {'session': IRONIC_SESSION,
                    'region_name': CONF.ironic.os_region}
        else:
            ironic_url = IRONIC_SESSION.get_endpoint(
                service_type=CONF.ironic.os_service_type,
                endpoint_type=CONF.ironic.os_endpoint_type,
                region_name=CONF.ironic.os_region
            )
            args = {'token': token,
                    'endpoint': ironic_url}
    args['os_ironic_api_version'] = api_version
    args['max_retries'] = CONF.ironic.max_retries
    args['retry_interval'] = CONF.ironic.retry_interval
    return client.Client(1, **args)


def check_provision_state(node, with_credentials=False):
    state = node.provision_state.lower()
    if with_credentials and state not in SET_CREDENTIALS_VALID_STATES:
        msg = _('Invalid provision state for setting IPMI credentials: '
                '"%(state)s", valid states are %(valid)s')
        raise utils.Error(msg % {'state': state,
                                 'valid': list(SET_CREDENTIALS_VALID_STATES)},
                          node_info=node)
    elif not with_credentials and state not in VALID_STATES:
        msg = _('Invalid provision state for introspection: '
                '"%(state)s", valid states are "%(valid)s"')
        raise utils.Error(msg % {'state': state, 'valid': list(VALID_STATES)},
                          node_info=node)


def capabilities_to_dict(caps):
    """Convert the Node's capabilities into a dictionary."""
    if not caps:
        return {}
    return dict([key.split(':', 1) for key in caps.split(',')])


def dict_to_capabilities(caps_dict):
    """Convert a dictionary into a string with the capabilities syntax."""
    return ','.join(["%s:%s" % (key, value)
                     for key, value in caps_dict.items()
                     if value is not None])


def get_node(node_id, ironic=None, **kwargs):
    """Get a node from Ironic.

    :param node_id: node UUID or name.
    :param ironic: ironic client instance.
    :param kwargs: arguments to pass to Ironic client.
    :raises: Error on failure
    """
    ironic = ironic if ironic is not None else get_client()

    try:
        return ironic.node.get(node_id, **kwargs)
    except ironic_exc.NotFound:
        raise NotFound(node_id)
    except ironic_exc.HttpError as exc:
        raise utils.Error(_("Cannot get node %(node)s: %(exc)s") %
                          {'node': node_id, 'exc': exc})


def list_opts():
    return keystone.add_auth_options(IRONIC_OPTS, IRONIC_GROUP)
