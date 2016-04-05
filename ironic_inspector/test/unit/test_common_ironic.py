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

import mock
import socket
import unittest

from ironicclient import client
from oslo_config import cfg

from ironic_inspector.common import ironic as ir_utils
from ironic_inspector.common import keystone
from ironic_inspector.test import base
from ironic_inspector import utils


CONF = cfg.CONF


@mock.patch.object(keystone, 'register_auth_opts')
@mock.patch.object(keystone, 'get_session')
@mock.patch.object(client, 'Client')
class TestGetClient(base.BaseTest):
    def setUp(self):
        super(TestGetClient, self).setUp()
        ir_utils.reset_ironic_session()
        self.cfg.config(auth_strategy='keystone')
        self.cfg.config(os_region='somewhere', group='ironic')
        self.addCleanup(ir_utils.reset_ironic_session)

    def test_get_client_with_auth_token(self, mock_client, mock_load,
                                        mock_opts):
        fake_token = 'token'
        fake_ironic_url = 'http://127.0.0.1:6385'
        mock_sess = mock.Mock()
        mock_sess.get_endpoint.return_value = fake_ironic_url
        mock_load.return_value = mock_sess
        ir_utils.get_client(fake_token)
        mock_sess.get_endpoint.assert_called_once_with(
            endpoint_type=CONF.ironic.os_endpoint_type,
            service_type=CONF.ironic.os_service_type,
            region_name=CONF.ironic.os_region)
        args = {'token': fake_token,
                'endpoint': fake_ironic_url,
                'os_ironic_api_version': ir_utils.DEFAULT_IRONIC_API_VERSION,
                'max_retries': CONF.ironic.max_retries,
                'retry_interval': CONF.ironic.retry_interval}
        mock_client.assert_called_once_with(1, **args)

    def test_get_client_without_auth_token(self, mock_client, mock_load,
                                           mock_opts):
        mock_sess = mock.Mock()
        mock_load.return_value = mock_sess
        ir_utils.get_client(None)
        args = {'session': mock_sess,
                'region_name': 'somewhere',
                'os_ironic_api_version': ir_utils.DEFAULT_IRONIC_API_VERSION,
                'max_retries': CONF.ironic.max_retries,
                'retry_interval': CONF.ironic.retry_interval}
        mock_client.assert_called_once_with(1, **args)


class TestGetIpmiAddress(base.BaseTest):
    def test_ipv4_in_resolves(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': '192.168.1.1'})
        ip = ir_utils.get_ipmi_address(node)
        self.assertEqual(ip, '192.168.1.1')

    @mock.patch('socket.gethostbyname')
    def test_good_hostname_resolves(self, mock_socket):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'www.example.com'})
        mock_socket.return_value = '192.168.1.1'
        ip = ir_utils.get_ipmi_address(node)
        mock_socket.assert_called_once_with('www.example.com')
        self.assertEqual(ip, '192.168.1.1')

    @mock.patch('socket.gethostbyname')
    def test_bad_hostname_errors(self, mock_socket):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'meow'},
                         uuid='uuid1')
        mock_socket.side_effect = socket.gaierror('Boom')
        self.assertRaises(utils.Error, ir_utils.get_ipmi_address, node)

    def test_additional_fields(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'foo': '192.168.1.1'})
        self.assertIsNone(ir_utils.get_ipmi_address(node))

        self.cfg.config(ipmi_address_fields=['foo', 'bar', 'baz'])
        ip = ir_utils.get_ipmi_address(node)
        self.assertEqual(ip, '192.168.1.1')

    def test_ipmi_bridging_enabled(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'www.example.com',
                                      'ipmi_bridging': 'single'})
        self.assertIsNone(ir_utils.get_ipmi_address(node))


class TestCapabilities(unittest.TestCase):

    def test_capabilities_to_dict(self):
        capabilities = 'cat:meow,dog:wuff'
        expected_output = {'cat': 'meow', 'dog': 'wuff'}
        output = ir_utils.capabilities_to_dict(capabilities)
        self.assertEqual(expected_output, output)

    def test_dict_to_capabilities(self):
        capabilities_dict = {'cat': 'meow', 'dog': 'wuff'}
        output = ir_utils.dict_to_capabilities(capabilities_dict)
        self.assertIn('cat:meow', output)
        self.assertIn('dog:wuff', output)
