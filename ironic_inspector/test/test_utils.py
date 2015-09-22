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
import unittest

from ironicclient import client
import keystoneclient.v2_0.client as keystone_client
from keystonemiddleware import auth_token
from oslo_config import cfg

from ironic_inspector.test import base
from ironic_inspector import utils

try:
    from unittest import mock
except ImportError:
    import mock

CONF = cfg.CONF


class TestCheckAuth(base.BaseTest):
    def setUp(self):
        super(TestCheckAuth, self).setUp()
        CONF.set_override('auth_strategy', 'keystone')

    @mock.patch.object(client, 'get_client')
    @mock.patch.object(keystone_client, 'Client')
    def test_get_client_with_auth_token(self, mock_keystone_client,
                                        mock_client):
        fake_token = 'token'
        fake_ironic_url = 'http://127.0.0.1:6385'
        mock_keystone_client().service_catalog.url_for.return_value = (
            fake_ironic_url)
        utils.get_client(fake_token)
        args = {'os_auth_token': fake_token,
                'ironic_url': fake_ironic_url,
                'os_ironic_api_version': '1.6',
                'max_retries': CONF.ironic.max_retries,
                'retry_interval': CONF.ironic.retry_interval}
        mock_client.assert_called_once_with(1, **args)

    @mock.patch.object(client, 'get_client')
    def test_get_client_without_auth_token(self, mock_client):
        utils.get_client(None)
        args = {'os_password': CONF.ironic.os_password,
                'os_username': CONF.ironic.os_username,
                'os_auth_url': CONF.ironic.os_auth_url,
                'os_tenant_name': CONF.ironic.os_tenant_name,
                'os_endpoint_type': CONF.ironic.os_endpoint_type,
                'os_service_type': CONF.ironic.os_service_type,
                'os_ironic_api_version': '1.6',
                'max_retries': CONF.ironic.max_retries,
                'retry_interval': CONF.ironic.retry_interval}
        mock_client.assert_called_once_with(1, **args)

    @mock.patch.object(auth_token, 'AuthProtocol')
    def test_middleware(self, mock_auth):
        CONF.set_override('admin_user', 'admin', 'keystone_authtoken')
        CONF.set_override('admin_tenant_name', 'admin', 'keystone_authtoken')
        CONF.set_override('admin_password', 'password', 'keystone_authtoken')
        CONF.set_override('auth_uri', 'http://127.0.0.1:5000/v2.0',
                          'keystone_authtoken')
        CONF.set_override('identity_uri', 'http://127.0.0.1:35357',
                          'keystone_authtoken')

        app = mock.Mock(wsgi_app=mock.sentinel.app)
        utils.add_auth_middleware(app)

        call_args = mock_auth.call_args_list[0]
        args = call_args[0]
        self.assertEqual(mock.sentinel.app, args[0])
        args1 = args[1]

        self.assertEqual('admin', args1['admin_user'])
        self.assertEqual('admin', args1['admin_tenant_name'])
        self.assertEqual('password', args1['admin_password'])
        self.assertEqual(True, args1['delay_auth_decision'])
        self.assertEqual('http://127.0.0.1:5000/v2.0', args1['auth_uri'])
        self.assertEqual('http://127.0.0.1:35357', args1['identity_uri'])

    @mock.patch.object(auth_token, 'AuthProtocol')
    def test_add_auth_middleware_with_deprecated_items(self, mock_auth):
        CONF.set_override('os_password', 'os_password', 'ironic')
        CONF.set_override('admin_password', 'admin_password',
                          'keystone_authtoken')
        CONF.set_override('os_username', 'os_username', 'ironic')
        CONF.set_override('admin_user', 'admin_user', 'keystone_authtoken')
        CONF.set_override('os_auth_url', 'os_auth_url', 'ironic')
        CONF.set_override('auth_uri', 'auth_uri', 'keystone_authtoken')
        CONF.set_override('os_tenant_name', 'os_tenant_name', 'ironic')
        CONF.set_override('admin_tenant_name', 'admin_tenant_name',
                          'keystone_authtoken')
        CONF.set_override('identity_uri', 'identity_uri_ironic', 'ironic')
        CONF.set_override('identity_uri', 'identity_uri', 'keystone_authtoken')

        app = mock.Mock(wsgi_app=mock.sentinel.app)
        utils.add_auth_middleware(app)

        call_args = mock_auth.call_args_list[0]
        args = call_args[0]
        self.assertEqual(mock.sentinel.app, args[0])
        args1 = args[1]
        self.assertEqual('os_password', args1['admin_password'])
        self.assertEqual('os_username', args1['admin_user'])
        self.assertEqual('os_auth_url', args1['auth_uri'])
        self.assertEqual('os_tenant_name', args1['admin_tenant_name'])
        self.assertTrue(args1['delay_auth_decision'])
        self.assertEqual('identity_uri_ironic', args1['identity_uri'])

    def test_ok(self):
        request = mock.Mock(headers={'X-Identity-Status': 'Confirmed',
                                     'X-Roles': 'admin,member'})
        utils.check_auth(request)

    def test_invalid(self):
        request = mock.Mock(headers={'X-Identity-Status': 'Invalid'})
        self.assertRaises(utils.Error, utils.check_auth, request)

    def test_not_admin(self):
        request = mock.Mock(headers={'X-Identity-Status': 'Confirmed',
                                     'X-Roles': 'member'})
        self.assertRaises(utils.Error, utils.check_auth, request)

    def test_disabled(self):
        CONF.set_override('auth_strategy', 'noauth')
        request = mock.Mock(headers={'X-Identity-Status': 'Invalid'})
        utils.check_auth(request)


class TestGetIpmiAddress(base.BaseTest):
    def test_ipv4_in_resolves(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': '192.168.1.1'})
        ip = utils.get_ipmi_address(node)
        self.assertEqual(ip, '192.168.1.1')

    @mock.patch('socket.gethostbyname')
    def test_good_hostname_resolves(self, mock_socket):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'www.example.com'})
        mock_socket.return_value = '192.168.1.1'
        ip = utils.get_ipmi_address(node)
        mock_socket.assert_called_once_with('www.example.com')
        self.assertEqual(ip, '192.168.1.1')

    @mock.patch('socket.gethostbyname')
    def test_bad_hostname_errors(self, mock_socket):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'meow'})
        mock_socket.side_effect = socket.gaierror('Boom')
        self.assertRaises(utils.Error, utils.get_ipmi_address, node)

    def test_additional_fields(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'foo': '192.168.1.1'})
        self.assertIsNone(utils.get_ipmi_address(node))

        CONF.set_override('ipmi_address_fields', ['foo', 'bar', 'baz'])
        ip = utils.get_ipmi_address(node)
        self.assertEqual(ip, '192.168.1.1')

    def test_ipmi_bridging_enabled(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'www.example.com',
                                      'ipmi_bridging': 'single'})
        self.assertIsNone(utils.get_ipmi_address(node))


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


class TestSpawnN(unittest.TestCase):

    def setUp(self):
        super(TestSpawnN, self).setUp()
        utils.GREEN_POOL = None

    @mock.patch('eventlet.greenpool.GreenPool', autospec=True)
    def test_spawn_n(self, mock_green_pool):
        greenpool = mock_green_pool.return_value
        func = lambda x: x

        utils.spawn_n(func, "hello")
        self.assertEqual(greenpool, utils.GREEN_POOL)
        greenpool.spawn_n.assert_called_with(func, "hello")

        utils.spawn_n(func, "goodbye")
        greenpool.spawn_n.assert_called_with(func, "goodbye")

        mock_green_pool.assert_called_once_with(CONF.max_concurrency)
