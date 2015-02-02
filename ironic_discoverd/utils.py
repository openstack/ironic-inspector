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
from keystoneclient import exceptions as keystone_exc
from keystoneclient.v2_0 import client as keystone
import six

from ironic_discoverd import conf


LOG = logging.getLogger('ironic_discoverd.utils')
OS_ARGS = ('os_password', 'os_username', 'os_auth_url', 'os_tenant_name')
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


def check_is_admin(token):
    """Check whether the token is from a user with the admin role.

    :param token: Keystone authentication token.
    :raises: keystoneclient.exceptions.Unauthorized if the user does not have
        the admin role in the tenant provided in the admin_tenant_name option.
    """
    kc = keystone.Client(token=token,
                         tenant_name=conf.get('discoverd',
                                              'admin_tenant_name'),
                         auth_url=conf.get('discoverd', 'os_auth_url'))
    if "admin" not in [role.name
                       for role in kc.roles.roles_for_user(
                           kc.user_id,
                           tenant=kc.tenant_id)]:
        raise keystone_exc.Unauthorized()


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
