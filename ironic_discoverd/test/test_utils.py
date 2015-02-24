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

import unittest

import eventlet
from ironicclient import exceptions
from keystoneclient import exceptions as keystone_exc
import mock

from ironic_discoverd import conf
from ironic_discoverd.test import base
from ironic_discoverd import utils


class TestCheckIsAdmin(base.BaseTest):
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


@mock.patch.object(eventlet.greenthread, 'sleep', lambda _: None)
class TestRetryOnConflict(unittest.TestCase):
    def test_retry_on_conflict(self):
        call = mock.Mock()
        call.side_effect = ([exceptions.Conflict()] * (utils.RETRY_COUNT - 1)
                            + [mock.sentinel.result])
        res = utils.retry_on_conflict(call, 1, 2, x=3)
        self.assertEqual(mock.sentinel.result, res)
        call.assert_called_with(1, 2, x=3)
        self.assertEqual(utils.RETRY_COUNT, call.call_count)

    def test_retry_on_conflict_fail(self):
        call = mock.Mock()
        call.side_effect = ([exceptions.Conflict()] * (utils.RETRY_COUNT + 1)
                            + [mock.sentinel.result])
        self.assertRaises(exceptions.Conflict, utils.retry_on_conflict,
                          call, 1, 2, x=3)
        call.assert_called_with(1, 2, x=3)
        self.assertEqual(utils.RETRY_COUNT, call.call_count)


class TestCapabilities(unittest.TestCase):

    def test_capabilities_to_dict(self):
        capabilities = 'cat:meow,dog:wuff'
        expected_output = {'cat': 'meow', 'dog': 'wuff'}
        output = utils.capabilities_to_dict(capabilities)
        self.assertEqual(expected_output, output)

    def test_dict_to_capabilities(self):
        capabilities_dict = {'cat': 'meow', 'dog': 'wuff'}
        output = utils.dict_to_capabilities(capabilities_dict)
        self.assertIn('cat:meow', output)
        self.assertIn('dog:wuff', output)
