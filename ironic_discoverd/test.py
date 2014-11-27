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

import os
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
from ironic_discoverd import node_cache
from ironic_discoverd.plugins import base as plugins_base
from ironic_discoverd.plugins import example as example_plugin
from ironic_discoverd import utils


class BaseTest(unittest.TestCase):
    def setUp(self):
        super(BaseTest, self).setUp()
        conf.init_conf()
        conf.CONF.add_section('discoverd')
        conf.CONF.set('discoverd', 'database', '')
        node_cache._DB_NAME = None
        self.db = node_cache._db()
        self.addCleanup(lambda: os.unlink(node_cache._DB_NAME))


@patch.object(example_plugin.ExampleProcessingHook, 'post_discover')
@patch.object(example_plugin.ExampleProcessingHook, 'pre_discover')
@patch.object(firewall, 'update_filters', autospec=True)
@patch.object(node_cache, 'pop_node', autospec=True)
@patch.object(utils, 'get_client', autospec=True)
class TestProcess(BaseTest):
    def setUp(self):
        self.node = Mock(driver_info={'ipmi_address': '1.2.3.4'},
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
            'ipmi_address': '1.2.3.4',
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
        self.port = Mock(uuid='port_uuid')

    def _do_test(self, client_mock, pop_mock, filters_mock, pre_mock,
                 post_mock):
        plugins_base._HOOKS_MGR = None
        conf.CONF.set('discoverd', 'processing_hooks', 'example')

        cli = client_mock.return_value

        def fake_port_create(node_uuid, address):
            if address == '11:22:33:44:55:66':
                return self.port
            else:
                raise exceptions.Conflict()

        cli.port.create.side_effect = fake_port_create
        pop_mock.return_value = self.node.uuid
        cli.node.get.return_value = self.node
        post_mock.return_value = (['fake patch', 'fake patch 2'],
                                  {'11:22:33:44:55:66': ['port patch']})

        discoverd.process(self.data)

        pop_mock.assert_called_once_with(bmc_address='1.2.3.4',
                                         mac=ANY)
        cli.node.get.assert_called_once_with(self.node.uuid)
        self.assertEqual(['11:22:33:44:55:66', '66:55:44:33:22:11'],
                         sorted(pop_mock.call_args[1]['mac']))

        cli.node.update.assert_called_once_with(self.node.uuid,
                                                self.patch + ['fake patch',
                                                              'fake patch 2'])
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='11:22:33:44:55:66')
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='66:55:44:33:22:11')
        self.assertEqual(2, cli.port.create.call_count)
        filters_mock.assert_called_once_with(cli)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')
        cli.port.update.assert_called_once_with(self.port.uuid, ['port patch'])

        pre_mock.assert_called_once_with(self.data)
        post_mock.assert_called_once_with(self.node, [self.port], self.data)

    def test_ok(self, client_mock, pop_mock, filters_mock, pre_mock,
                post_mock):
        self._do_test(client_mock, pop_mock, filters_mock, pre_mock, post_mock)

    def test_deprecated_macs(self, client_mock, pop_mock, filters_mock,
                             pre_mock, post_mock):
        del self.data['interfaces']
        self.data['macs'] = self.macs
        self._do_test(client_mock, pop_mock, filters_mock, pre_mock, post_mock)

    def test_ports_for_inactive(self, client_mock, pop_mock, filters_mock,
                                pre_mock, post_mock):
        del self.data['interfaces']['em4']
        conf.CONF.set('discoverd', 'ports_for_inactive_interfaces',
                      'true')
        self._do_test(client_mock, pop_mock, filters_mock, pre_mock, post_mock)

    def test_not_found(self, client_mock, pop_mock, filters_mock, pre_mock,
                       post_mock):
        cli = client_mock.return_value
        pop_mock.return_value = None

        discoverd.process(self.data)

        self.assertFalse(cli.node.update.called)
        self.assertFalse(cli.port.create.called)
        self.assertFalse(cli.node.set_power_state.called)

    def test_not_found_in_ironic(self, client_mock, pop_mock, filters_mock,
                                 pre_mock, post_mock):
        cli = client_mock.return_value
        pop_mock.return_value = self.node.uuid
        cli.node.get.side_effect = exceptions.NotFound()

        discoverd.process(self.data)

        cli.node.get.assert_called_once_with(self.node.uuid)
        self.assertFalse(cli.node.update.called)
        self.assertFalse(cli.port.create.called)
        self.assertFalse(cli.node.set_power_state.called)


@patch.object(eventlet.greenthread, 'spawn_n',
              side_effect=lambda f, *a: f(*a) and None)
@patch.object(firewall, 'update_filters', autospec=True)
@patch.object(node_cache, 'add_node', autospec=True)
@patch.object(utils, 'get_client', autospec=True)
class TestDiscover(BaseTest):
    def setUp(self):
        super(TestDiscover, self).setUp()
        self.node1 = Mock(driver='pxe_ssh',
                          uuid='uuid1',
                          driver_info={},
                          maintenance=True,
                          instance_uuid=None,
                          # allowed with maintenance=True
                          power_state='power on')
        self.node2 = Mock(driver='pxe_ipmitool',
                          uuid='uuid2',
                          driver_info={'ipmi_address': '1.2.3.4'},
                          maintenance=False,
                          instance_uuid=None,
                          power_state=None,
                          extra={'on_discovery': True})
        self.node3 = Mock(driver='pxe_ipmitool',
                          uuid='uuid3',
                          driver_info={'ipmi_address': '1.2.3.5'},
                          maintenance=False,
                          instance_uuid=None,
                          power_state='power off',
                          extra={'on_discovery': True})

    @patch.object(time, 'time', lambda: 42.0)
    def test_ok(self, client_mock, add_mock, filters_mock, spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            self.node2,
            self.node3,
        ]
        ports = [
            [Mock(address='1-1'), Mock(address='1-2')],
            [Mock(address='2-1'), Mock(address='2-2')],
            [Mock(address='3-1'), Mock(address='3-2')],
        ]
        cli.node.list_ports.side_effect = ports

        discoverd.discover(['uuid1', 'uuid2', 'uuid3'])

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
                                 mac=['3-1', '3-2'])
        filters_mock.assert_called_once_with(cli)
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

    def test_failed_to_get_node(self, client_mock, add_mock, filters_mock,
                                spawn_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            self.node1,
            exceptions.NotFound(),
        ]
        self.assertRaisesRegexp(utils.DiscoveryFailed,
                                'Cannot find node uuid2',
                                discoverd.discover, ['uuid1', 'uuid2'])

        cli.node.get.side_effect = [
            exceptions.Conflict(),
            self.node1,
        ]
        self.assertRaisesRegexp(utils.DiscoveryFailed,
                                'Cannot get node uuid1',
                                discoverd.discover, ['uuid1', 'uuid2'])

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
            Mock(power={'result': True}),
            Mock(power={'result': False, 'reason': 'oops'}),
        ]
        self.assertRaisesRegexp(
            utils.DiscoveryFailed,
            'Failed validation of power interface for node uuid2',
            discoverd.discover, ['uuid1', 'uuid2'])

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
                                discoverd.discover, [])
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
            discoverd.discover, ['uuid1', 'uuid2'])

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
            discoverd.discover, ['uuid1', 'uuid2'])

        self.assertEqual(2, cli.node.get.call_count)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)


class TestApi(BaseTest):
    def setUp(self):
        super(TestApi, self).setUp()
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
        discover_mock.side_effect = utils.DiscoveryFailed("boom")
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
class TestCheckIronicAvailable(BaseTest):
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


class TestNodeCache(BaseTest):
    def setUp(self):
        super(TestNodeCache, self).setUp()
        self.node = Mock(driver_info={'ipmi_address': '1.2.3.4'},
                         uuid='uuid')
        self.macs = ['11:22:33:44:55:66', '66:55:44:33:22:11']

    def test_add_node(self):
        # Ensure previous node information is cleared
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.execute("insert into nodes(uuid) values('uuid2')")
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', self.node.uuid))

        node_cache.add_node(self.node.uuid, mac=self.macs,
                            bmc_address='1.2.3.4', foo=None)

        res = self.db.execute("select uuid, started_at "
                              "from nodes order by uuid").fetchall()
        self.assertEqual(['uuid', 'uuid2'], [t[0] for t in res])
        self.assertTrue(time.time() - 60 < res[0][1] < time.time() + 60)

        res = self.db.execute("select name, value, uuid from attributes "
                              "order by name, value").fetchall()
        self.assertEqual([('bmc_address', '1.2.3.4', 'uuid'),
                          ('mac', '11:22:33:44:55:66', 'uuid'),
                          ('mac', '66:55:44:33:22:11', 'uuid')],
                         res)

    def test_add_node_duplicate_mac(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            ('another-uuid',))
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', 'another-uuid'))

        self.assertRaises(utils.DiscoveryFailed,
                          node_cache.add_node,
                          self.node.uuid, mac=['11:22:11:22:11:22'])

    def test_drop_node(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.execute("insert into nodes(uuid) values('uuid2')")
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', self.node.uuid))

        node_cache.drop_node(self.node.uuid)

        self.assertEqual([('uuid2',)], self.db.execute(
            "select uuid from nodes").fetchall())
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_macs_on_discovery(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.executemany("insert into attributes(name, value, uuid) "
                                "values(?, ?, ?)",
                                [('mac', '11:22:11:22:11:22', self.node.uuid),
                                 ('mac', '22:11:22:11:22:11', self.node.uuid)])
        self.assertEqual({'11:22:11:22:11:22', '22:11:22:11:22:11'},
                         node_cache.macs_on_discovery())


class TestNodeCachePop(BaseTest):
    def setUp(self):
        super(TestNodeCachePop, self).setUp()
        self.uuid = 'uuid'
        self.macs = ['11:22:33:44:55:66', '66:55:44:33:22:11']
        self.macs2 = ['00:00:00:00:00:00']
        node_cache.add_node(self.uuid,
                            bmc_address='1.2.3.4',
                            mac=self.macs)

    def test_no_data(self):
        self.assertIsNone(node_cache.pop_node())
        self.assertIsNone(node_cache.pop_node(mac=[]))

    def test_bmc(self):
        res = node_cache.pop_node(bmc_address='1.2.3.4')
        self.assertEqual(self.uuid, res)
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_macs(self):
        res = node_cache.pop_node(mac=['11:22:33:33:33:33', self.macs[1]])
        self.assertEqual(self.uuid, res)
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_macs_not_found(self):
        res = node_cache.pop_node(mac=['11:22:33:33:33:33',
                                       '66:66:44:33:22:11'])
        self.assertIsNone(res)

    def test_macs_multiple_found(self):
        node_cache.add_node('uuid2', mac=self.macs2)
        res = node_cache.pop_node(mac=[self.macs[0], self.macs2[0]])
        self.assertIsNone(res)

    def test_both(self):
        res = node_cache.pop_node(bmc_address='1.2.3.4',
                                  mac=self.macs)
        self.assertEqual(self.uuid, res)
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())


class TestPlugins(unittest.TestCase):
    @patch.object(example_plugin.ExampleProcessingHook, 'pre_discover',
                  autospec=True)
    @patch.object(example_plugin.ExampleProcessingHook, 'post_discover',
                  autospec=True)
    def test_hook(self, mock_post, mock_pre):
        plugins_base._HOOKS_MGR = None
        conf.CONF.set('discoverd', 'processing_hooks', 'example')
        mgr = plugins_base.processing_hooks_manager()
        mgr.map_method('pre_discover', 'node_info')
        mock_pre.assert_called_once_with(ANY, 'node_info')
        mgr.map_method('post_discover', 'node', ['port'], 'node_info')
        mock_post.assert_called_once_with(ANY, 'node', ['port'], 'node_info')


if __name__ == '__main__':
    unittest.main()
