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

import logging as pylog
import re

import futurist
from keystonemiddleware import auth_token
from oslo_config import cfg
from oslo_log import log
from oslo_middleware import cors as cors_middleware
import six

from ironic_inspector.common.i18n import _, _LE
from ironic_inspector import conf  # noqa

CONF = cfg.CONF

_EXECUTOR = None


def get_ipmi_address_from_data(introspection_data):
    try:
        return introspection_data['inventory']['bmc_address']
    except KeyError:
        return introspection_data.get('ipmi_address')


def get_pxe_mac(introspection_data):
    pxe_mac = introspection_data.get('boot_interface')
    if pxe_mac and '-' in pxe_mac:
        # pxelinux format: 01-aa-bb-cc-dd-ee-ff
        pxe_mac = pxe_mac.split('-', 1)[1]
        pxe_mac = pxe_mac.replace('-', ':').lower()
    return pxe_mac


def processing_logger_prefix(data=None, node_info=None):
    """Calculate prefix for logging.

    Tries to use:
    * node UUID,
    * node PXE MAC,
    * node BMC address

    :param data: introspection data
    :param node_info: NodeInfo or ironic node object
    :return: logging prefix as a string
    """
    # TODO(dtantsur): try to get MAC and BMC address for node_info as well
    parts = []
    data = data or {}

    if node_info is not None:
        parts.append(str(node_info.uuid))

    pxe_mac = get_pxe_mac(data)
    if pxe_mac:
        parts.append('MAC %s' % pxe_mac)

    if CONF.processing.log_bmc_address:
        bmc_address = get_ipmi_address_from_data(data) if data else None
        if bmc_address:
            parts.append('BMC %s' % bmc_address)

    if parts:
        return _('[node: %s]') % ' '.join(parts)
    else:
        return _('[unidentified node]')


class ProcessingLoggerAdapter(log.KeywordArgumentAdapter):
    def process(self, msg, kwargs):
        if 'data' not in kwargs and 'node_info' not in kwargs:
            return super(ProcessingLoggerAdapter, self).process(msg, kwargs)

        data = kwargs.get('data', {})
        node_info = kwargs.get('node_info')
        prefix = processing_logger_prefix(data, node_info)

        msg, kwargs = super(ProcessingLoggerAdapter, self).process(msg, kwargs)
        return ('%s %s' % (prefix, msg)), kwargs


def getProcessingLogger(name):
    # We can't use getLogger from oslo_log, as it's an adapter itself
    logger = pylog.getLogger(name)
    return ProcessingLoggerAdapter(logger, {})


LOG = getProcessingLogger(__name__)


class Error(Exception):
    """Inspector exception."""

    def __init__(self, msg, code=400, log_level='error', **kwargs):
        super(Error, self).__init__(msg)
        getattr(LOG, log_level)(msg, **kwargs)
        self.http_code = code


class NotFoundInCacheError(Error):
    """Exception when node was not found in cache during processing."""

    def __init__(self, msg, code=404):
        super(NotFoundInCacheError, self).__init__(msg, code,
                                                   log_level='info')


def executor():
    """Return the current futures executor."""
    global _EXECUTOR
    if _EXECUTOR is None:
        _EXECUTOR = futurist.GreenThreadPoolExecutor(
            max_workers=CONF.max_concurrency)
    return _EXECUTOR


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


def add_cors_middleware(app):
    """Create a CORS wrapper

    Attach ironic-inspector-specific defaults that must be included
    in all CORS responses.

    :param app: application
    """
    app.wsgi_app = cors_middleware.CORS(app.wsgi_app, CONF)


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
