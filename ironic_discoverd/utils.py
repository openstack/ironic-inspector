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

import logging
import re

import eventlet
from ironicclient import client
from ironicclient import exceptions
from keystonemiddleware import auth_token
import six

from ironic_discoverd import conf


LOG = logging.getLogger('ironic_discoverd.utils')
OS_ARGS = ('os_password', 'os_username', 'os_auth_url', 'os_tenant_name')
MIDDLEWARE_ARGS = ('admin_password', 'admin_user', 'auth_uri',
                   'admin_tenant_name')
RETRY_COUNT = 12
RETRY_DELAY = 5


class Error(Exception):
    """Discoverd exception."""

    def __init__(self, msg, code=400):
        super(Error, self).__init__(msg)
        LOG.error(msg)
        self.http_code = code


def get_client():  # pragma: no cover
    """Get Ironic client instance."""
    args = dict((k, conf.get('discoverd', k)) for k in OS_ARGS)
    return client.get_client(1, **args)


def add_auth_middleware(app):
    """Add authentication middleware to Flask application.

    :param app: application.
    """
    auth_conf = {key: conf.get('discoverd', value)
                 for (key, value) in zip(MIDDLEWARE_ARGS, OS_ARGS)}
    auth_conf['delay_auth_decision'] = True
    auth_conf['identity_uri'] = conf.get('discoverd', 'identity_uri')
    app.wsgi_app = auth_token.AuthProtocol(app.wsgi_app, auth_conf)


def check_auth(request):
    """Check authentication on request.

    :param request: Flask request
    :raises: utils.Error if access is denied
    """
    if not conf.getboolean('discoverd', 'authenticate'):
        return
    if request.headers.get('X-Identity-Status').lower() == 'invalid':
        raise Error('Authentication required', code=401)
    roles = (request.headers.get('X-Roles') or '').split(',')
    if 'admin' not in roles:
        LOG.error('Role "admin" not in user role list %s', roles)
        raise Error('Access denied', code=403)


def is_valid_mac(address):
    """Return whether given value is a valid MAC."""
    m = "[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
    return (isinstance(address, six.string_types)
            and re.match(m, address.lower()))


def retry_on_conflict(call, *args, **kwargs):
    """Wrapper to retry 409 CONFLICT exceptions."""
    for i in range(RETRY_COUNT):
        try:
            return call(*args, **kwargs)
        except exceptions.Conflict as exc:
            LOG.warning('Conflict on calling %s: %s, retry attempt %d',
                        getattr(call, '__name__', repr(call)), exc, i + 1)
            if i == RETRY_COUNT - 1:
                raise
            eventlet.greenthread.sleep(RETRY_DELAY)

    raise RuntimeError('unreachable code')  # pragma: no cover
