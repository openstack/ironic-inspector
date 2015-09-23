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

import re
import socket

import eventlet
from ironicclient import client
import keystoneclient.v2_0.client as keystone_client
from keystonemiddleware import auth_token
from oslo_config import cfg
from oslo_log import log
import six

from ironic_inspector.common.i18n import _, _LE, _LW

CONF = cfg.CONF

# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'manageable', 'inspecting', 'inspectfail'}
SET_CREDENTIALS_VALID_STATES = {'enroll'}


LOG = log.getLogger('ironic_inspector.utils')

GREEN_POOL = None

# 1.6 is a Kilo API version, which has all we need and is pretty well tested
DEFAULT_IRONIC_API_VERSION = '1.6'


class Error(Exception):
    """Inspector exception."""

    def __init__(self, msg, code=400):
        super(Error, self).__init__(msg)
        LOG.error(msg)
        self.http_code = code


class NotFoundInCacheError(Error):
    """Exception when node was not found in cache during processing."""

    def __init__(self, msg, code=404):
        super(NotFoundInCacheError, self).__init__(msg, code)


def spawn_n(*args, **kwargs):
    global GREEN_POOL
    if not GREEN_POOL:
        GREEN_POOL = eventlet.greenpool.GreenPool(CONF.max_concurrency)
    return GREEN_POOL.spawn_n(*args, **kwargs)


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
        ironic_url = keystone.service_catalog.url_for(
            service_type=CONF.ironic.os_service_type,
            endpoint_type=CONF.ironic.os_endpoint_type)
        args = {'os_auth_token': token,
                'ironic_url': ironic_url}
    args['os_ironic_api_version'] = api_version
    args['max_retries'] = CONF.ironic.max_retries
    args['retry_interval'] = CONF.ironic.retry_interval
    return client.get_client(1, **args)


def add_auth_middleware(app):
    """Add authentication middleware to Flask application.

    :param app: application.
    """
    auth_conf = dict(CONF.keystone_authtoken)
    # These items should only be used for accessing Ironic API.
    # For keystonemiddleware's authentication,
    # keystone_authtoken's items will be used and
    # these items will be unsupported.
    # [ironic]/os_password
    # [ironic]/os_username
    # [ironic]/os_auth_url
    # [ironic]/os_tenant_name
    auth_conf.update({'admin_password':
                      CONF.ironic.os_password or
                      CONF.keystone_authtoken.admin_password,
                      'admin_user':
                      CONF.ironic.os_username or
                      CONF.keystone_authtoken.admin_user,
                      'auth_uri':
                      CONF.ironic.os_auth_url or
                      CONF.keystone_authtoken.auth_uri,
                      'admin_tenant_name':
                      CONF.ironic.os_tenant_name or
                      CONF.keystone_authtoken.admin_tenant_name,
                      'identity_uri':
                      CONF.ironic.identity_uri or
                      CONF.keystone_authtoken.identity_uri})
    auth_conf['delay_auth_decision'] = True
    app.wsgi_app = auth_token.AuthProtocol(app.wsgi_app, auth_conf)


def check_auth(request):
    """Check authentication on request.

    :param request: Flask request
    :raises: utils.Error if access is denied
    """
    if get_auth_strategy() == 'noauth':
        return
    if request.headers.get('X-Identity-Status').lower() == 'invalid':
        raise Error(_('Authentication required'), code=401)
    roles = (request.headers.get('X-Roles') or '').split(',')
    if 'admin' not in roles:
        LOG.error(_LE('Role "admin" not in user role list %s'), roles)
        raise Error(_('Access denied'), code=403)


def is_valid_mac(address):
    """Return whether given value is a valid MAC."""
    m = "[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
    return (isinstance(address, six.string_types)
            and re.match(m, address.lower()))


def get_auth_strategy():
    if CONF.authenticate is not None:
        return 'keystone' if CONF.authenticate else 'noauth'
    return CONF.auth_strategy


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
                raise Error(msg % (value, node.uuid))


def check_provision_state(node, with_credentials=False):
    if node.maintenance:
        LOG.warn(_LW('Introspecting nodes in maintenance mode is deprecated, '
                     'accepted states: %s'), VALID_STATES)
        return

    state = node.provision_state.lower()
    if with_credentials and state not in SET_CREDENTIALS_VALID_STATES:
        msg = _('Invalid provision state "%(state)s" for setting IPMI '
                'credentials on node %(node)s, valid states are %(valid)s')
        raise Error(msg % {'node': node.uuid, 'state': state,
                           'valid': list(SET_CREDENTIALS_VALID_STATES)})
    elif not with_credentials and state not in VALID_STATES:
        msg = _('Invalid provision state "%(state)s" for introspection of '
                'node %(node)s, valid states are "%(valid)s"')
        raise Error(msg % {'node': node.uuid, 'state': state,
                           'valid': list(VALID_STATES)})


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
