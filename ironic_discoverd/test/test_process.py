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

import functools
import time

import eventlet
from ironicclient import exceptions
import mock

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd.plugins import example as example_plugin
from ironic_discoverd import process
from ironic_discoverd.test import base as test_base
from ironic_discoverd import utils


class BaseTest(test_base.NodeTest):
    def setUp(self):
        super(BaseTest, self).setUp()
        conf.CONF.set('discoverd', 'processing_hooks',
                      'ramdisk_error,scheduler,validate_interfaces')
        self.started_at = time.time()
        self.all_macs = self.macs + ['DE:AD:BE:EF:DE:AD']
        self.data = {
            'ipmi_address': self.bmc_address,
            'cpus': 2,
            'cpu_arch': 'x86_64',
            'memory_mb': 1024,
            'local_gb': 20,
            'interfaces': {
                'em1': {'mac': self.macs[0], 'ip': '1.2.0.1'},
                'em2': {'mac': self.macs[1], 'ip': '1.2.0.2'},
                'em3': {'mac': self.all_macs[2]},
            }
        }
        self.ports = [
            mock.Mock(uuid='port_uuid%d' % i, address=mac)
            for i, mac in enumerate(self.macs)
        ]


@mock.patch.object(process, '_process_node', autospec=True)
@mock.patch.object(node_cache, 'find_node', autospec=True)
@mock.patch.object(utils, 'get_client', autospec=True)
class TestProcess(BaseTest):
    def setUp(self):
        super(TestProcess, self).setUp()
        self.fake_result_json = 'node json'

    def prepare_mocks(func):
        @functools.wraps(func)
        def wrapper(self, client_mock, pop_mock, process_mock, *args, **kw):
            cli = client_mock.return_value
            pop_mock.return_value = node_cache.NodeInfo(
                uuid=self.node.uuid,
                started_at=self.started_at)
            cli.port.create.side_effect = self.ports
            cli.node.get.return_value = self.node
            process_mock.return_value = self.fake_result_json

            return func(self, cli, pop_mock, process_mock, *args, **kw)

        return wrapper

    @prepare_mocks
    def test_ok(self, cli, pop_mock, process_mock):
        res = process.process(self.data)

        self.assertEqual(self.fake_result_json, res)

        # By default interfaces w/o IP are dropped
        self.assertEqual(['em1', 'em2'], sorted(self.data['interfaces']))
        self.assertEqual(self.macs, sorted(self.data['macs']))

        pop_mock.assert_called_once_with(bmc_address=self.bmc_address,
                                         mac=self.data['macs'])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli, cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_no_ipmi(self, cli, pop_mock, process_mock):
        del self.data['ipmi_address']
        process.process(self.data)

        pop_mock.assert_called_once_with(bmc_address=None,
                                         mac=self.data['macs'])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli, cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_deprecated_macs(self, cli, pop_mock, process_mock):
        del self.data['interfaces']
        self.data['macs'] = self.macs
        process.process(self.data)

        self.assertEqual(self.macs, sorted(i['mac'] for i in
                                           self.data['interfaces'].values()))
        self.assertEqual(self.macs, sorted(self.data['macs']))

        pop_mock.assert_called_once_with(bmc_address=self.bmc_address,
                                         mac=self.data['macs'])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli, cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_ports_for_inactive(self, cli, pop_mock, process_mock):
        conf.CONF.set('discoverd', 'ports_for_inactive_interfaces', 'true')
        process.process(self.data)

        self.assertEqual(['em1', 'em2', 'em3'],
                         sorted(self.data['interfaces']))
        self.assertEqual(self.all_macs, sorted(self.data['macs']))

        pop_mock.assert_called_once_with(bmc_address=self.bmc_address,
                                         mac=self.data['macs'])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli, cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_invalid_interfaces(self, cli, pop_mock, process_mock):
        self.data['interfaces'] = {
            'br1': {'mac': 'broken', 'ip': '1.2.0.1'},
            'br2': {'mac': '', 'ip': '1.2.0.2'},
            'br3': {},
        }

        process.process(self.data)

        self.assertEqual({}, self.data['interfaces'])
        self.assertEqual([], self.data['macs'])

        pop_mock.assert_called_once_with(bmc_address=self.bmc_address,
                                         mac=[])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli, cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_error(self, cli, pop_mock, process_mock):
        self.data['error'] = 'BOOM'

        self.assertRaisesRegexp(utils.Error,
                                'BOOM',
                                process.process, self.data)
        self.assertFalse(process_mock.called)

    @prepare_mocks
    def test_missing_required(self, cli, pop_mock, process_mock):
        del self.data['cpus']

        self.assertRaisesRegexp(utils.Error,
                                'missing',
                                process.process, self.data)
        self.assertFalse(process_mock.called)

    @prepare_mocks
    def test_not_found_in_cache(self, cli, pop_mock, process_mock):
        pop_mock.side_effect = utils.Error('not found')

        self.assertRaisesRegexp(utils.Error,
                                'not found',
                                process.process, self.data)
        self.assertFalse(cli.node.get.called)
        self.assertFalse(process_mock.called)

    @prepare_mocks
    def test_not_found_in_ironic(self, cli, pop_mock, process_mock):
        cli.node.get.side_effect = exceptions.NotFound()

        self.assertRaisesRegexp(utils.Error,
                                'not found',
                                process.process, self.data)
        cli.node.get.assert_called_once_with(self.uuid)
        self.assertFalse(process_mock.called)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_expected_exception(self, finished_mock, client_mock, pop_mock,
                                process_mock):
        pop_mock.return_value = node_cache.NodeInfo(
            uuid=self.node.uuid,
            started_at=self.started_at)
        process_mock.side_effect = utils.Error('boom')

        self.assertRaisesRegexp(utils.Error, 'boom',
                                process.process, self.data)

        finished_mock.assert_called_once_with(mock.ANY, error='boom')

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_unexpected_exception(self, finished_mock, client_mock, pop_mock,
                                  process_mock):
        pop_mock.return_value = node_cache.NodeInfo(
            uuid=self.node.uuid,
            started_at=self.started_at)
        process_mock.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Unexpected exception during processing')


@mock.patch.object(eventlet.greenthread, 'spawn_n',
                   lambda f, *a: f(*a) and None)
@mock.patch.object(eventlet.greenthread, 'sleep', lambda _: None)
@mock.patch.object(example_plugin.ExampleProcessingHook, 'before_update')
@mock.patch.object(firewall, 'update_filters', autospec=True)
class TestProcessNode(BaseTest):
    def setUp(self):
        super(TestProcessNode, self).setUp()
        conf.CONF.set('discoverd', 'processing_hooks',
                      'ramdisk_error,scheduler,validate_interfaces,example')
        self.validate_attempts = 5
        self.power_off_attempts = 2
        self.data['macs'] = self.macs  # validate_interfaces hook
        self.cached_node = node_cache.NodeInfo(uuid=self.uuid,
                                               started_at=self.started_at)
        self.patch_before = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '2'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '1024'},
        ]  # scheduler hook
        self.patch_after = [
            {'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
            {'op': 'remove', 'path': '/extra/on_discovery'},
        ]

        self.cli = mock.Mock()
        self.cli.node.validate.side_effect = self.fake_validate()
        self.cli.port.create.side_effect = self.ports
        self.cli.node.update.return_value = self.node
        # Simulate longer power off
        self.cli.node.get.side_effect = (
            [self.node] * self.power_off_attempts
            + [mock.Mock(power_state='power off')])

    def fake_validate(self):
        # Simulate long ramdisk task
        for _ in range(self.validate_attempts):
            yield mock.Mock(power={'result': False, 'reason': 'boom!'})
        yield mock.Mock(power={'result': True})

    def call(self):
        return process._process_node(self.cli, self.node, self.data,
                                     self.cached_node)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_ok(self, finished_mock, filters_mock, post_hook_mock):
        self.call()

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.cli.node.update.assert_any_call(self.uuid, self.patch_before)
        self.cli.node.update.assert_any_call(self.uuid, self.patch_after)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.assertFalse(self.cli.node.validate.called)
        self.assertEqual(self.power_off_attempts + 1,
                         self.cli.node.get.call_count)

        post_hook_mock.assert_called_once_with(self.node, mock.ANY,
                                               self.data)
        # List is built from a dict - order is undefined
        self.assertEqual(self.ports, sorted(post_hook_mock.call_args[0][1],
                                            key=lambda p: p.address))
        finished_mock.assert_called_once_with(mock.ANY)

    def test_overwrite(self, filters_mock, post_hook_mock):
        conf.CONF.set('discoverd', 'overwrite_existing', 'true')
        patch = [
            {'path': '/properties/cpus', 'value': '2', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '1024', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '20', 'op': 'add'}]

        self.call()

        self.cli.node.update.assert_any_call(self.uuid, patch)
        self.cli.node.update.assert_any_call(self.uuid, self.patch_after)

    def test_update_retry_on_conflict(self, filters_mock, post_hook_mock):
        self.cli.node.update.side_effect = [exceptions.Conflict, self.node,
                                            exceptions.Conflict, self.node]

        self.call()

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.cli.node.update.assert_any_call(self.uuid, self.patch_before)
        self.cli.node.update.assert_any_call(self.uuid, self.patch_after)
        self.assertEqual(4, self.cli.node.update.call_count)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')

    def test_power_off_retry_on_conflict(self, filters_mock, post_hook_mock):
        self.cli.node.set_power_state.side_effect = [exceptions.Conflict, None]

        self.call()

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.cli.node.update.assert_any_call(self.uuid, self.patch_before)
        self.cli.node.update.assert_any_call(self.uuid, self.patch_after)
        self.cli.node.set_power_state.assert_called_with(self.uuid, 'off')
        self.assertEqual(2, self.cli.node.set_power_state.call_count)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    @mock.patch.object(time, 'time')
    def test_power_off_timeout(self, time_mock, finished_mock, filters_mock,
                               post_hook_mock):
        conf.CONF.set('discoverd', 'timeout', '100')
        time_mock.return_value = self.started_at + 1000
        self.cli.node.get.return_value = self.node

        self.assertRaisesRegexp(utils.Error, 'power off', self.call)

        self.cli.node.update.assert_called_once_with(self.uuid,
                                                     self.patch_before)
        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Timeout waiting for node uuid to power off '
            'after introspection')

    def test_port_failed(self, filters_mock, post_hook_mock):
        self.ports[0] = exceptions.Conflict()

        self.call()

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.cli.node.update.assert_any_call(self.uuid, self.patch_before)
        self.cli.node.update.assert_any_call(self.uuid, self.patch_after)

        post_hook_mock.assert_called_once_with(self.node, self.ports[1:],
                                               self.data)

    def test_hook_patches(self, filters_mock, post_hook_mock):
        node_patches = ['node patch1', 'node patch2']
        port_patch = ['port patch']
        post_hook_mock.return_value = (node_patches,
                                       {self.macs[1]: port_patch})

        self.call()

        self.cli.node.update.assert_any_call(self.uuid,
                                             self.patch_before + node_patches)
        self.cli.node.update.assert_any_call(self.uuid, self.patch_after)
        self.cli.port.update.assert_called_once_with(self.ports[1].uuid,
                                                     port_patch)

    def test_ipmi_setup_credentials(self, filters_mock, post_hook_mock):
        self.cached_node.set_option('setup_ipmi_credentials', True)

        self.call()

        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.cli.node.validate.assert_called_with(self.uuid)
        self.assertEqual(self.validate_attempts + 1,
                         self.cli.node.validate.call_count)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    @mock.patch.object(time, 'time')
    def test_ipmi_setup_credentials_timeout(self, time_mock, finished_mock,
                                            filters_mock, post_hook_mock):
        conf.CONF.set('discoverd', 'timeout', '100')
        self.cached_node.set_option('setup_ipmi_credentials', True)
        time_mock.return_value = self.started_at + 1000

        self.call()

        self.cli.node.update.assert_called_once_with(self.uuid,
                                                     self.patch_before)
        self.assertFalse(self.cli.node.set_power_state.called)
        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Timeout waiting for power credentials update of node uuid '
            'after introspection')

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_power_off_failed(self, finished_mock, filters_mock,
                              post_hook_mock):
        self.cli.node.set_power_state.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(utils.Error, 'Failed to power off',
                                self.call)

        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.cli.node.update.assert_called_once_with(self.uuid,
                                                     self.patch_before)
        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Failed to power off node uuid, check it\'s power management'
            ' configuration: boom')
