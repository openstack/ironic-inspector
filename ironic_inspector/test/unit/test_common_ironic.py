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
from unittest import mock

import openstack
from openstack import exceptions as os_exc

from ironic_inspector.common import ironic as ir_utils
from ironic_inspector.common import keystone
from ironic_inspector.test import base
from ironic_inspector import utils


@mock.patch.object(keystone, 'get_session', autospec=True)
@mock.patch.object(openstack.connection, 'Connection', autospec=True)
class TestGetClientBase(base.BaseTest):
    def setUp(self):
        super(TestGetClientBase, self).setUp()
        ir_utils.reset_ironic_session()

    def test_get_client(self, mock_connection, mock_session):
        for i in range(3):
            cli = ir_utils.get_client()
            self.assertIs(mock_connection.return_value.baremetal, cli)
        mock_session.assert_called_once_with('ironic')
        mock_connection.assert_called_once_with(
            session=mock_session.return_value, oslo_conf=ir_utils.CONF)


class TestGetIpmiAddress(base.BaseTest):
    def setUp(self):
        super(TestGetIpmiAddress, self).setUp()
        self.ipmi_address = 'www.example.com'
        self.ipmi_ipv4 = '192.168.1.1'
        self.ipmi_ipv6 = 'fe80::1'

    def test_ipv4_in_resolves(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': self.ipmi_ipv4})
        self.assertEqual((self.ipmi_ipv4, self.ipmi_ipv4, None),
                         ir_utils.get_ipmi_address(node))

    def test_ipv6_in_resolves(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': self.ipmi_ipv6})
        self.assertEqual((self.ipmi_ipv6, None, self.ipmi_ipv6),
                         ir_utils.get_ipmi_address(node))

    @mock.patch('socket.getaddrinfo', autospec=True)
    def test_good_hostname_resolves(self, mock_socket):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': self.ipmi_address})
        mock_socket.return_value = [
            (socket.AF_INET, None, None, None, (self.ipmi_ipv4,)),
            (socket.AF_INET6, None, None, None, (self.ipmi_ipv6,))]
        self.assertEqual((self.ipmi_address, self.ipmi_ipv4, self.ipmi_ipv6),
                         ir_utils.get_ipmi_address(node))
        mock_socket.assert_called_once_with(self.ipmi_address, None, 0, 0,
                                            socket.SOL_TCP)

    def test_additional_fields(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'foo': self.ipmi_ipv4})
        self.assertEqual((None, None, None),
                         ir_utils.get_ipmi_address(node))

        self.cfg.config(ipmi_address_fields=['foo', 'bar', 'baz'])
        self.assertEqual((self.ipmi_ipv4, self.ipmi_ipv4, None),
                         ir_utils.get_ipmi_address(node))

    def test_ipmi_bridging_enabled(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': 'www.example.com',
                                      'ipmi_bridging': 'single'})
        self.assertEqual((None, None, None),
                         ir_utils.get_ipmi_address(node))

    def test_loopback_address(self):
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'ipmi_address': '127.0.0.2'})
        self.assertEqual((None, None, None),
                         ir_utils.get_ipmi_address(node))

    @mock.patch.object(socket, 'getaddrinfo', autospec=True)
    def test_redfish_bmc_address(self, mock_socket):
        self.cfg.config(ipmi_address_fields=['redfish_address'])
        url = 'http://{}/path'.format(self.ipmi_address)
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'redfish_address': url})
        mock_socket.return_value = [
            (socket.AF_INET, None, None, None, (self.ipmi_ipv4,)),
            (socket.AF_INET6, None, None, None, (self.ipmi_ipv6,))]
        self.assertEqual((self.ipmi_address, self.ipmi_ipv4, self.ipmi_ipv6),
                         ir_utils.get_ipmi_address(node))
        mock_socket.assert_called_once_with(self.ipmi_address, None, 0, 0, 6)

    @mock.patch.object(socket, 'getaddrinfo', autospec=True)
    def test_redfish_bmc_address_ipv4(self, mock_socket):
        self.cfg.config(ipmi_address_fields=['redfish_address'])
        url = 'http://{}:8080/path'.format(self.ipmi_ipv4)
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'redfish_address': url})
        mock_socket.return_value = [
            (socket.AF_INET, None, None, None, (self.ipmi_ipv4,))]
        self.assertEqual((self.ipmi_ipv4, self.ipmi_ipv4, None),
                         ir_utils.get_ipmi_address(node))
        mock_socket.assert_called_once_with(self.ipmi_ipv4, None, 0, 0, 6)

    @mock.patch.object(socket, 'getaddrinfo', autospec=True)
    def test_redfish_bmc_address_ipv6(self, mock_socket):
        self.cfg.config(ipmi_address_fields=['redfish_address'])
        url = 'https://[{}]::443/path'.format(self.ipmi_ipv6)
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'redfish_address': url})
        mock_socket.return_value = [
            (socket.AF_INET6, None, None, None, (self.ipmi_ipv6,))]
        self.assertEqual((self.ipmi_ipv6, None, self.ipmi_ipv6),
                         ir_utils.get_ipmi_address(node))
        mock_socket.assert_called_once_with(self.ipmi_ipv6, None, 0, 0, 6)

    def test_redfish_bmc_address_ipv6_brackets_no_scheme(self):
        self.cfg.config(ipmi_address_fields=['redfish_address'])
        address = '[{}]'.format(self.ipmi_ipv6)
        node = mock.Mock(spec=['driver_info', 'uuid'],
                         driver_info={'redfish_address': address})
        self.assertEqual((self.ipmi_ipv6, None, self.ipmi_ipv6),
                         ir_utils.get_ipmi_address(node))


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


class TestCallWithRetries(unittest.TestCase):
    def setUp(self):
        super(TestCallWithRetries, self).setUp()
        self.call = mock.Mock(spec=[])

    def test_no_retries_on_success(self):
        result = ir_utils.call_with_retries(self.call, 'meow', answer=42)
        self.assertEqual(result, self.call.return_value)
        self.call.assert_called_once_with('meow', answer=42)

    def test_no_retries_on_python_error(self):
        self.call.side_effect = RuntimeError('boom')
        self.assertRaisesRegex(RuntimeError, 'boom',
                               ir_utils.call_with_retries,
                               self.call, 'meow', answer=42)
        self.call.assert_called_once_with('meow', answer=42)

    @mock.patch('time.sleep', lambda _x: None)
    def test_retries_on_ironicclient_error(self):
        self.call.side_effect = [
            os_exc.SDKException('boom')
        ] * 3 + [mock.sentinel.result]

        result = ir_utils.call_with_retries(self.call, 'meow', answer=42)
        self.assertEqual(result, mock.sentinel.result)
        self.call.assert_called_with('meow', answer=42)
        self.assertEqual(4, self.call.call_count)

    @mock.patch('time.sleep', lambda _x: None)
    def test_retries_on_ironicclient_error_with_failure(self):
        self.call.side_effect = os_exc.SDKException('boom')
        self.assertRaisesRegex(os_exc.SDKException, 'boom',
                               ir_utils.call_with_retries,
                               self.call, 'meow', answer=42)
        self.call.assert_called_with('meow', answer=42)
        self.assertEqual(5, self.call.call_count)


class TestLookupNode(base.NodeTest):
    def setUp(self):
        super(TestLookupNode, self).setUp()
        self.ironic = mock.Mock(spec=['nodes', 'ports'],
                                nodes=mock.Mock(spec=['list']),
                                ports=mock.Mock(spec=['list']))
        self.ironic.nodes.return_value = [self.node]
        # Simulate only the PXE port enrolled
        self.port = mock.Mock(address=self.pxe_mac, node_id=self.node.uuid)
        self.ironic.ports.side_effect = [
            [self.port]
        ] + [[]] * (len(self.macs) - 1)

    def test_no_input_no_result(self):
        self.assertIsNone(ir_utils.lookup_node())

    def test_lookup_by_mac_only(self):
        uuid = ir_utils.lookup_node(macs=self.macs, ironic=self.ironic)
        self.assertEqual(self.node.uuid, uuid)
        self.ironic.ports.assert_has_calls([
            mock.call(address=mac,
                      fields=['uuid', 'node_uuid']) for mac in self.macs
        ])

    def test_lookup_by_mac_duplicates(self):
        self.ironic.ports.side_effect = [
            [self.port],
            [mock.Mock(address=self.inactive_mac, node_id='another')]
        ] + [[]] * (len(self.macs) - 1)
        self.assertRaisesRegex(utils.Error, 'more than one node',
                               ir_utils.lookup_node,
                               macs=self.macs, ironic=self.ironic)
        self.ironic.ports.assert_has_calls([
            mock.call(address=mac,
                      fields=['uuid', 'node_uuid']) for mac in self.macs
        ])

    def test_lookup_by_bmc_only(self):
        uuid = ir_utils.lookup_node(bmc_addresses=[self.bmc_address,
                                                   '42.42.42.42'],
                                    ironic=self.ironic)
        self.assertEqual(self.node.uuid, uuid)
        self.assertEqual(1, self.ironic.nodes.call_count)

    def test_lookup_by_bmc_duplicates(self):
        self.ironic.nodes.return_value = [
            self.node,
            mock.Mock(id='another',
                      driver_info={'ipmi_address': '42.42.42.42'}),
        ]
        self.assertRaisesRegex(utils.Error, 'more than one node',
                               ir_utils.lookup_node,
                               bmc_addresses=[self.bmc_address,
                                              '42.42.42.42'],
                               ironic=self.ironic)
        self.assertEqual(1, self.ironic.nodes.call_count)

    def test_lookup_by_both(self):
        uuid = ir_utils.lookup_node(bmc_addresses=[self.bmc_address,
                                                   self.bmc_v6address],
                                    macs=self.macs,
                                    ironic=self.ironic)
        self.assertEqual(self.node.uuid, uuid)
        self.ironic.ports.assert_has_calls([
            mock.call(address=mac,
                      fields=['uuid', 'node_uuid']) for mac in self.macs
        ])
        self.assertEqual(1, self.ironic.nodes.call_count)

    def test_lookup_by_both_duplicates(self):
        self.ironic.ports.side_effect = [
            [mock.Mock(address=self.inactive_mac, node_id='another')]
        ] + [[]] * (len(self.macs) - 1)
        self.assertRaisesRegex(utils.Error, 'correspond to different nodes',
                               ir_utils.lookup_node,
                               bmc_addresses=[self.bmc_address,
                                              self.bmc_v6address],
                               macs=self.macs,
                               ironic=self.ironic)
        self.ironic.ports.assert_has_calls([
            mock.call(address=mac,
                      fields=['uuid', 'node_uuid']) for mac in self.macs
        ])
        self.assertEqual(1, self.ironic.nodes.call_count)
