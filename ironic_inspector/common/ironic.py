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
from keystoneclient import client as keystone_client
from oslo_config import cfg

from ironic_inspector.common.i18n import _
from ironic_inspector import utils

CONF = cfg.CONF

# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'manageable', 'inspecting', 'inspectfail'}
SET_CREDENTIALS_VALID_STATES = {'enroll'}

# 1.11 is API version, which support 'enroll' state
DEFAULT_IRONIC_API_VERSION = '1.11'

IRONIC_GROUP = 'ironic'

IRONIC_OPTS = [
    cfg.StrOpt('os_auth_url',
               default='',
               help='Keystone authentication endpoint for accessing Ironic '
                    'API. Use [keystone_authtoken]/auth_uri for keystone '
                    'authentication.',
               deprecated_group='discoverd'),
    cfg.StrOpt('os_username',
               default='',
               help='User name for accessing Ironic API. '
                    'Use [keystone_authtoken]/admin_user for keystone '
                    'authentication.',
               deprecated_group='discoverd'),
    cfg.StrOpt('os_password',
               default='',
               help='Password for accessing Ironic API. '
                    'Use [keystone_authtoken]/admin_password for keystone '
                    'authentication.',
               secret=True,
               deprecated_group='discoverd'),
    cfg.StrOpt('os_tenant_name',
               default='',
               help='Tenant name for accessing Ironic API. '
                    'Use [keystone_authtoken]/admin_tenant_name for keystone '
                    'authentication.',
               deprecated_group='discoverd'),
    cfg.StrOpt('identity_uri',
               default='',
               help='Keystone admin endpoint. '
                    'DEPRECATED: use [keystone_authtoken]/identity_uri.',
               deprecated_group='discoverd',
               deprecated_for_removal=True),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help='Method to use for authentication: noauth or keystone.'),
    cfg.StrOpt('ironic_url',
               default='http://localhost:6385/',
               help='Ironic API URL, used to set Ironic API URL when '
                    'auth_strategy option is noauth to work with standalone '
                    'Ironic without keystone.'),
    cfg.StrOpt('os_service_type',
               default='baremetal',
               help='Ironic service type.'),
    cfg.StrOpt('os_endpoint_type',
               default='internalURL',
               help='Ironic endpoint type.'),
    cfg.IntOpt('retry_interval',
               default=2,
               help='Interval between retries in case of conflict error '
               '(HTTP 409).'),
    cfg.IntOpt('max_retries',
               default=30,
               help='Maximum number of retries in case of conflict error '
               '(HTTP 409).'),
]


CONF.register_opts(IRONIC_OPTS, group=IRONIC_GROUP)


def get_ipmi_address(node):
    ipmi_fields = ['ipmi_address'] + CONF.ipmi_address_fields
    # NOTE(sambetts): IPMI Address is useless to us if bridging is enabled so
    # just ignore it and return None
    if node.driver_info.get("ipmi_bridging", "no") != "no":
        return
    for name in ipmi_fields:
        value = node.driver_info.get(name)
        if value:
            try:
                ip = socket.gethostbyname(value)
                return ip
            except socket.gaierror:
                msg = ('Failed to resolve the hostname (%s) for node %s')
                raise utils.Error(msg % (value, node.uuid), node_info=node)


def get_client(token=None,
               api_version=DEFAULT_IRONIC_API_VERSION):  # pragma: no cover
    """Get Ironic client instance."""
    # NOTE: To support standalone ironic without keystone
    if CONF.ironic.auth_strategy == 'noauth':
        args = {'os_auth_token': 'noauth',
                'ironic_url': CONF.ironic.ironic_url}
    elif token is None:
        args = {'os_password': CONF.ironic.os_password,
                'os_username': CONF.ironic.os_username,
                'os_auth_url': CONF.ironic.os_auth_url,
                'os_tenant_name': CONF.ironic.os_tenant_name,
                'os_service_type': CONF.ironic.os_service_type,
                'os_endpoint_type': CONF.ironic.os_endpoint_type}
    else:
        keystone_creds = {'password': CONF.ironic.os_password,
                          'username': CONF.ironic.os_username,
                          'auth_url': CONF.ironic.os_auth_url,
                          'tenant_name': CONF.ironic.os_tenant_name}
        keystone = keystone_client.Client(**keystone_creds)
        # FIXME(sambetts): Work around for Bug 1539839 as client.authenticate
        # is not called.
        keystone.authenticate()
        ironic_url = keystone.service_catalog.url_for(
            service_type=CONF.ironic.os_service_type,
            endpoint_type=CONF.ironic.os_endpoint_type)
        args = {'os_auth_token': token,
                'ironic_url': ironic_url}
    args['os_ironic_api_version'] = api_version
    args['max_retries'] = CONF.ironic.max_retries
    args['retry_interval'] = CONF.ironic.retry_interval
    return client.get_client(1, **args)


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


def list_opts():
    return [(IRONIC_GROUP, IRONIC_OPTS)]
