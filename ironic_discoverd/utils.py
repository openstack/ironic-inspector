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

from ironicclient import client
from keystoneclient.v2_0 import client as keystone
import six

from ironic_discoverd import conf


LOG = logging.getLogger('discoverd')
OS_ARGS = ('os_password', 'os_username', 'os_auth_url', 'os_tenant_name')


class DiscoveryFailed(Exception):
    def __init__(self, msg, code=400):
        super(DiscoveryFailed, self).__init__(msg)
        self.http_code = code


def get_client():  # pragma: no cover
    args = dict((k, conf.get('discoverd', k)) for k in OS_ARGS)
    return client.get_client(1, **args)


def get_keystone(token):  # pragma: no cover
    return keystone.Client(token=token, auth_url=conf.get('discoverd',
                                                          'os_auth_url'))


def is_valid_mac(address):
    m = "[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
    return (isinstance(address, six.string_types)
            and re.match(m, address.lower()))
