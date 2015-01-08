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

from keystoneclient import exceptions as keystone_exc
import mock

from ironic_discoverd import conf
from ironic_discoverd.test import base
from ironic_discoverd import utils


class TestUtils(base.BaseTest):

    @mock.patch('keystoneclient.v2_0.client.Client')
    def test_admin_token(self, mock_ks):
        conf.CONF.set('discoverd', 'os_auth_url', '127.0.0.1')
        fake_client = mock_ks.return_value
        mockAdmin = mock.Mock()
        mockAdmin.name = 'admin'
        fake_client.roles.roles_for_user.return_value = [mockAdmin]
        utils.check_is_admin('token')

    @mock.patch('keystoneclient.v2_0.client.Client')
    def test_non_admin_token(self, mock_ks):
        conf.CONF.set('discoverd', 'os_auth_url', '127.0.0.1')
        fake_client = mock_ks.return_value
        mockMember = mock.Mock()
        mockMember.name = 'member'
        fake_client.roles.roles_for_user.return_value = [mockMember]
        self.assertRaises(keystone_exc.Unauthorized,
                          utils.check_is_admin, 'token')
