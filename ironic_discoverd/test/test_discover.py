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

import time

import eventlet
from ironicclient import exceptions
import mock

from ironic_discoverd import discover
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd.test import base as test_base
from ironic_discoverd import utils


@mock.patch.object(eventlet.greenthread, 'spawn_n',
                   side_effect=lambda f, *a: f(*a) and None)
@mock.patch.object(firewall, 'update_filters', autospec=True)
@mock.patch.object(node_cache, 'add_node', autospec=True)
@mock.patch.object(utils, 'get_client', autospec=True)
class TestDiscover(test_base.BaseTest):
    def setUp(self):
        super(TestDiscover, self).setUp()
        self.node1 = mock.Mock(driver='pxe_ssh',
                               uuid='uuid1',
                               driver_info={},
                               maintenance=True,
                               instance_uuid=None,
                               # allowed with maintenance=True
                               power_state='power on')
        self.node2 = mock.Mock(driver='pxe_ipmitool',
                               uuid='uuid2',
                               driver_info={'ipmi_address': '1.2.3.4'},
                               maintenance=False,
                               instance_uuid=None,
                               power_state=None,
                               extra={'on_discovery': True})
        self.node3 = mock.Mock(driver='pxe_ipmitool',
                               uuid='uuid3',
                               driver_info={'ipmi_address': '1.2.3.5'},
                               maintenance=False,
                               instance_uuid=None,
                               power_state='power off',
                               extra={'on_discovery': True})

    @mock.patch.object(time, 'time', lambda: 42.0)
    def test_ok(self, client_mock, add_mock, filters_mock, spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
            self.node3,
        ]
        ports = [
            [mock.Mock(address='1-1'), mock.Mock(address='1-2')],
            [mock.Mock(address='2-1'), mock.Mock(address='2-2')],
            [],
        ]
        cli.node.list_ports.side_effect = ports
        # Failure to powering on does not cause total failure
        cli.node.set_power_state.side_effect = [None,
                                                exceptions.Conflict(),
                                                None]

        discover.discover(['uuid1', 'uuid2', 'uuid3'])

        self.assertEqual(3, cli.node.get.call_count)
        self.assertEqual(3, cli.node.list_ports.call_count)
        self.assertEqual(3, add_mock.call_count)
        cli.node.list_ports.assert_any_call('uuid1', limit=0)
        cli.node.list_ports.assert_any_call('uuid2', limit=0)
        cli.node.list_ports.assert_any_call('uuid3', limit=0)
        add_mock.assert_any_call(self.node1.uuid,
                                 bmc_address=None,
                                 mac=['1-1', '1-2'])
        add_mock.assert_any_call(self.node2.uuid,
                                 bmc_address='1.2.3.4',
                                 mac=['2-1', '2-2'])
        add_mock.assert_any_call(self.node3.uuid,
                                 bmc_address='1.2.3.5',
                                 mac=[])
        filters_mock.assert_called_with(cli)
        self.assertEqual(2, filters_mock.call_count)  # 1 node w/o ports
        self.assertEqual(3, cli.node.set_power_state.call_count)
        cli.node.set_power_state.assert_called_with(mock.ANY, 'reboot')
        patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'},
                 {'op': 'add', 'path': '/extra/discovery_timestamp',
                  'value': '42.0'}]
        cli.node.update.assert_any_call('uuid1', patch)
        cli.node.update.assert_any_call('uuid2', patch)
        cli.node.update.assert_any_call('uuid3', patch)
        self.assertEqual(3, cli.node.update.call_count)
        spawn_mock.assert_called_with(discover._background_start_discover,
                                      cli, mock.ANY)
        self.assertEqual(3, spawn_mock.call_count)

    def test_failed_to_get_node(self, client_mock, add_mock, filters_mock,
                                spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            exceptions.NotFound(),
        ]
        self.assertRaisesRegexp(utils.DiscoveryFailed,
                                'Cannot find node uuid2',
                                discover.discover, ['uuid1', 'uuid2'])

        cli.node.get.side_effect = [
            exceptions.Conflict(),
            self.node1,
        ]
        self.assertRaisesRegexp(utils.DiscoveryFailed,
                                'Cannot get node uuid1',
                                discover.discover, ['uuid1', 'uuid2'])

        self.assertEqual(3, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)

    def test_failed_to_validate_node(self, client_mock, add_mock, filters_mock,
                                     spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
        ]
        cli.node.validate.side_effect = [
            mock.Mock(power={'result': True}),
            mock.Mock(power={'result': False, 'reason': 'oops'}),
        ]
        self.assertRaisesRegexp(
            utils.DiscoveryFailed,
            'Failed validation of power interface for node uuid2',
            discover.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(2, cli.node.validate.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)

    def test_no_uuids(self, client_mock, add_mock, filters_mock, spawn_mock):
        self.assertRaisesRegexp(utils.DiscoveryFailed,
                                'No nodes to discover',
                                discover.discover, [])
        self.assertFalse(client_mock.called)
        self.assertFalse(add_mock.called)

    def test_with_instance_uuid(self, client_mock, add_mock, filters_mock,
                                spawn_mock):
        self.node2.instance_uuid = 'uuid'
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
        ]
        self.assertRaisesRegexp(
            utils.DiscoveryFailed,
            'node uuid2 with assigned instance uuid',
            discover.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)

    def test_wrong_power_state(self, client_mock, add_mock, filters_mock,
                               spawn_mock):
        self.node2.power_state = 'power on'
        self.node2.maintenance = False
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
        ]
        self.assertRaisesRegexp(
            utils.DiscoveryFailed,
            'node uuid2 with power state "power on"',
            discover.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)
