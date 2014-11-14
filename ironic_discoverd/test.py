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

import eventlet
eventlet.monkey_patch(thread=False)

import time
import unittest

from ironicclient import exceptions
from keystoneclient import exceptions as keystone_exc
from mock import patch, Mock, ANY  # noqa

from ironic_discoverd import client
from ironic_discoverd import conf
from ironic_discoverd import discoverd
from ironic_discoverd import firewall
from ironic_discoverd import main
from ironic_discoverd import utils


def init_conf():
    conf.init_conf()
    conf.CONF.add_section('discoverd')


# FIXME(dtantsur): this test suite is far from being complete
@patch.object(firewall, 'update_filters', autospec=True)
@patch.object(utils, 'get_client', autospec=True)
class TestProcess(unittest.TestCase):
    def setUp(self):
        self.node = Mock(driver_info={},
                         properties={'cpu_arch': 'i386', 'local_gb': 40},
                         uuid='uuid',
                         extra={'on_discovery': 'true'})
        self.patch = [
            {'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
            {'op': 'remove', 'path': '/extra/on_discovery'},
            {'op': 'add', 'path': '/properties/cpus', 'value': '2'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '1024'},
        ]
        self.data = {
            'cpus': 2,
            'cpu_arch': 'x86_64',
            'memory_mb': 1024,
            'local_gb': 20,
            'interfaces': {
                'em1': {'mac': '11:22:33:44:55:66', 'ip': '1.2.3.4'},
                'em2': {'mac': 'broken', 'ip': '1.2.3.4'},
                'em3': {'mac': '', 'ip': '1.2.3.4'},
                'em4': {'mac': '66:55:44:33:22:11', 'ip': '1.2.3.4'},
                'em5': {'mac': '66:55:44:33:22:11'},
            }
        }
        self.macs = ['11:22:33:44:55:66', 'broken', '', '66:55:44:33:22:11']
        firewall.MACS_DISCOVERY = set(['11:22:33:44:55:66',
                                       '66:55:44:33:22:11'])
        init_conf()

    def _do_test_bmc(self, client_mock, filters_mock):
        self.node.driver_info['ipmi_address'] = '1.2.3.4'
        cli = client_mock.return_value
        cli.node.list.return_value = [
            Mock(driver_info={}),
            Mock(driver_info={'ipmi_address': '4.3.2.1'}),
            self.node,
            Mock(driver_info={'ipmi_address': '1.2.1.2'}),
        ]
        cli.port.create.side_effect = [None, exceptions.Conflict()]

        self.data['ipmi_address'] = '1.2.3.4'
        discoverd.process(self.data)

        self.assertTrue(cli.node.list.called)
        self.assertFalse(cli.port.get_by_address.called)
        cli.node.update.assert_called_once_with(self.node.uuid, self.patch)
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='11:22:33:44:55:66')
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='66:55:44:33:22:11')
        self.assertEqual(2, cli.port.create.call_count)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(), firewall.MACS_DISCOVERY)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')

    def test_bmc(self, client_mock, filters_mock):
        self._do_test_bmc(client_mock, filters_mock)

    def test_bmc_deprecated_macs(self, client_mock, filters_mock):
        del self.data['interfaces']
        self.data['macs'] = self.macs
        self._do_test_bmc(client_mock, filters_mock)

    def test_bmc_ports_for_inactive(self, client_mock, filters_mock):
        del self.data['interfaces']['em4']
        conf.CONF.set('discoverd', 'ports_for_inactive_interfaces',
                      'true')
        self._do_test_bmc(client_mock, filters_mock)

    def test_macs(self, client_mock, filters_mock):
        discoverd.ALLOW_SEARCH_BY_MAC = True
        cli = client_mock.return_value
        cli.port.get_by_address.side_effect = [
            exceptions.NotFound(), Mock(node_uuid=self.node.uuid)]
        cli.port.create.side_effect = [None, exceptions.Conflict()]
        cli.node.get.return_value = self.node

        discoverd.process(self.data)

        self.assertFalse(cli.node.list.called)
        cli.port.get_by_address.assert_any_call('11:22:33:44:55:66')
        cli.port.get_by_address.assert_any_call('66:55:44:33:22:11')
        cli.node.get.assert_called_once_with(self.node.uuid)
        cli.node.update.assert_called_once_with(self.node.uuid, self.patch)
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='11:22:33:44:55:66')
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='66:55:44:33:22:11')
        self.assertEqual(2, cli.port.create.call_count)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(), firewall.MACS_DISCOVERY)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')


@patch.object(eventlet.greenthread, 'spawn_n',
              side_effect=lambda f, *a: f(*a) and None)
@patch.object(firewall, 'update_filters', autospec=True)
@patch.object(utils, 'get_client', autospec=True)
class TestDiscover(unittest.TestCase):
    def setUp(self):
        super(TestDiscover, self).setUp()
        self.node1 = Mock(driver='pxe_ssh',
                          uuid='uuid1',
                          maintenance=True,
                          instance_uuid=None,
                          # allowed with maintenance=True
                          power_state='power on')
        self.node2 = Mock(driver='pxe_ipmitool',
                          uuid='uuid2',
                          maintenance=False,
                          instance_uuid=None,
                          power_state=None,
                          extra={'on_discovery': True})
        self.node3 = Mock(driver='pxe_ipmitool',
                          uuid='uuid3',
                          maintenance=False,
                          instance_uuid=None,
                          power_state='power off',
                          extra={'on_discovery': True})
        firewall.MACS_DISCOVERY = set()
        init_conf()

    @patch.object(time, 'time', lambda: 42.0)
    def test_ok(self, client_mock, filters_mock, spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
            self.node3,
        ]
        cli.node.list_ports.return_value = [Mock(address='1'),
                                            Mock(address='2')]

        discoverd.discover(['uuid1', 'uuid2', 'uuid3'])

        self.assertEqual(3, cli.node.get.call_count)
        self.assertEqual(3, cli.node.list_ports.call_count)
        cli.node.list_ports.assert_any_call('uuid1', limit=0)
        cli.node.list_ports.assert_any_call('uuid2', limit=0)
        cli.node.list_ports.assert_any_call('uuid3', limit=0)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(['1', '2']), firewall.MACS_DISCOVERY)
        self.assertEqual(3, cli.node.set_power_state.call_count)
        cli.node.set_power_state.assert_called_with(ANY, 'reboot')
        patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'},
                 {'op': 'add', 'path': '/extra/discovery_timestamp',
                  'value': '42.0'}]
        cli.node.update.assert_any_call('uuid1', patch)
        cli.node.update.assert_any_call(
            'uuid2',
            patch +
            [{'op': 'replace', 'path': '/maintenance', 'value': 'true'}])
        cli.node.update.assert_any_call(
            'uuid3',
            patch +
            [{'op': 'replace', 'path': '/maintenance', 'value': 'true'}])
        self.assertEqual(3, cli.node.update.call_count)
        spawn_mock.assert_called_once_with(discoverd._background_discover,
                                           cli, ANY)

    def test_failed_to_get_node(self, client_mock, filters_mock, spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            exceptions.NotFound(),
        ]
        self.assertRaisesRegexp(discoverd.DiscoveryFailed,
                                'Cannot find node uuid2',
                                discoverd.discover, ['uuid1', 'uuid2'])

        cli.node.get.side_effect = [
            exceptions.Conflict(),
            self.node1,
        ]
        self.assertRaisesRegexp(discoverd.DiscoveryFailed,
                                'Cannot get node uuid1',
                                discoverd.discover, ['uuid1', 'uuid2'])

        self.assertEqual(3, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)

    def test_failed_to_validate_node(self, client_mock, filters_mock,
                                     spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
        ]
        cli.node.validate.side_effect = [
            Mock(power={'result': True}),
            Mock(power={'result': False, 'reason': 'oops'}),
        ]
        self.assertRaisesRegexp(
            discoverd.DiscoveryFailed,
            'Failed validation of power interface for node uuid2',
            discoverd.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(2, cli.node.validate.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)

    def test_no_uuids(self, client_mock, filters_mock, spawn_mock):
        self.assertRaisesRegexp(discoverd.DiscoveryFailed,
                                'No nodes to discover',
                                discoverd.discover, [])
        self.assertFalse(client_mock.called)

    def test_with_instance_uuid(self, client_mock, filters_mock, spawn_mock):
        self.node2.instance_uuid = 'uuid'
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
        ]
        self.assertRaisesRegexp(
            discoverd.DiscoveryFailed,
            'node uuid2 with assigned instance uuid',
            discoverd.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)

    def test_wrong_power_state(self, client_mock, filters_mock, spawn_mock):
        self.node2.power_state = 'power on'
        self.node2.maintenance = False
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
        ]
        self.assertRaisesRegexp(
            discoverd.DiscoveryFailed,
            'node uuid2 with power state "power on"',
            discoverd.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)


class TestApi(unittest.TestCase):
    def setUp(self):
        init_conf()
        main.app.config['TESTING'] = True
        self.app = main.app.test_client()

    @patch.object(discoverd, 'discover', autospec=True)
    def test_discover_no_authentication(self, discover_mock):
        conf.CONF.set('discoverd', 'authenticate', 'false')
        res = self.app.post('/v1/discover', data='["uuid1"]')
        self.assertEqual(202, res.status_code)
        discover_mock.assert_called_once_with(["uuid1"])

    @patch.object(discoverd, 'discover', autospec=True)
    def test_discover_failed(self, discover_mock):
        conf.CONF.set('discoverd', 'authenticate', 'false')
        discover_mock.side_effect = discoverd.DiscoveryFailed("boom")
        res = self.app.post('/v1/discover', data='["uuid1"]')
        self.assertEqual(400, res.status_code)
        self.assertEqual(b"boom", res.data)
        discover_mock.assert_called_once_with(["uuid1"])

    @patch.object(discoverd, 'discover', autospec=True)
    def test_discover_missing_authentication(self, discover_mock):
        conf.CONF.set('discoverd', 'authenticate', 'true')
        res = self.app.post('/v1/discover', data='["uuid1"]')
        self.assertEqual(401, res.status_code)
        self.assertFalse(discover_mock.called)

    @patch.object(utils, 'get_keystone', autospec=True)
    @patch.object(discoverd, 'discover', autospec=True)
    def test_discover_failed_authentication(self, discover_mock,
                                            keystone_mock):
        conf.CONF.set('discoverd', 'authenticate', 'true')
        keystone_mock.side_effect = keystone_exc.Unauthorized()
        res = self.app.post('/v1/discover', data='["uuid1"]',
                            headers={'X-Auth-Token': 'token'})
        self.assertEqual(403, res.status_code)
        self.assertFalse(discover_mock.called)
        keystone_mock.assert_called_once_with(token='token')

    @patch.object(eventlet.greenthread, 'spawn_n')
    def test_continue(self, spawn_mock):
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(202, res.status_code)
        spawn_mock.assert_called_once_with(discoverd.process, "JSON")


@patch.object(client.requests, 'post', autospec=True)
class TestClient(unittest.TestCase):
    def test_client(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_client_full_url(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port/v1/",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_client_default_url(self, mock_post):
        client.discover(['uuid1', 'uuid2'],
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:5050/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )


@patch.object(eventlet.greenthread, 'sleep', autospec=True)
@patch.object(utils, 'get_client')
class TestCheckIronicAvailable(unittest.TestCase):
    def setUp(self):
        super(TestCheckIronicAvailable, self).setUp()
        init_conf()

    def test_ok(self, client_mock, sleep_mock):
        utils.check_ironic_available()
        client_mock.return_value.driver.list.assert_called_once_with()
        self.assertFalse(sleep_mock.called)

    def test_2_attempts(self, client_mock, sleep_mock):
        cli = Mock()
        client_mock.side_effect = [Exception(), cli]
        utils.check_ironic_available()
        self.assertEqual(2, client_mock.call_count)
        cli.driver.list.assert_called_once_with()
        sleep_mock.assert_called_once_with(
            conf.getint('discoverd', 'ironic_retry_period'))

    def test_failed(self, client_mock, sleep_mock):
        attempts = conf.getint('discoverd', 'ironic_retry_attempts')
        client_mock.side_effect = RuntimeError()
        self.assertRaises(RuntimeError, utils.check_ironic_available)
        self.assertEqual(1 + attempts, client_mock.call_count)
        self.assertEqual(attempts, sleep_mock.call_count)


if __name__ == '__main__':
    unittest.main()
