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
import json
import time

import eventlet
from ironicclient import exceptions
import mock
from oslo_config import cfg

from ironic_inspector import firewall
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector.plugins import example as example_plugin
from ironic_inspector import process
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = cfg.CONF


class BaseTest(test_base.NodeTest):
    def setUp(self):
        super(BaseTest, self).setUp()
        self.started_at = time.time()
        self.pxe_mac = self.macs[1]
        self.data = {
            'ipmi_address': self.bmc_address,
            'cpus': 2,
            'cpu_arch': 'x86_64',
            'memory_mb': 1024,
            'local_gb': 20,
            'interfaces': {
                'em1': {'mac': self.macs[0], 'ip': '1.2.0.1'},
                'em2': {'mac': self.macs[1], 'ip': '1.2.0.2'},
                'em3': {'mac': 'DE:AD:BE:EF:DE:AD'},
            },
            'boot_interface': '01-' + self.pxe_mac.replace(':', '-'),
        }
        self.all_ports = [
            mock.Mock(uuid='port_uuid%d' % i, address=mac)
            for i, mac in enumerate(self.macs)
        ]
        self.ports = [self.all_ports[1]]


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
            pop_mock.return_value.finished = mock.Mock()
            cli.node.get.return_value = self.node
            process_mock.return_value = self.fake_result_json

            return func(self, cli, pop_mock, process_mock, *args, **kw)

        return wrapper

    @prepare_mocks
    def test_ok(self, cli, pop_mock, process_mock):
        res = process.process(self.data)

        self.assertEqual(self.fake_result_json, res)

        # Only boot interface is added by default
        self.assertEqual(['em2'], sorted(self.data['interfaces']))
        self.assertEqual([self.pxe_mac], self.data['macs'])

        pop_mock.assert_called_once_with(bmc_address=self.bmc_address,
                                         mac=self.data['macs'])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_no_ipmi(self, cli, pop_mock, process_mock):
        del self.data['ipmi_address']
        process.process(self.data)

        pop_mock.assert_called_once_with(bmc_address=None,
                                         mac=self.data['macs'])
        cli.node.get.assert_called_once_with(self.uuid)
        process_mock.assert_called_once_with(cli.node.get.return_value,
                                             self.data, pop_mock.return_value)

    @prepare_mocks
    def test_not_found_in_cache(self, cli, pop_mock, process_mock):
        pop_mock.side_effect = iter([utils.Error('not found')])

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
        pop_mock.return_value.finished.assert_called_once_with(error=mock.ANY)

    @prepare_mocks
    def test_expected_exception(self, cli, pop_mock, process_mock):
        process_mock.side_effect = iter([utils.Error('boom')])

        self.assertRaisesRegexp(utils.Error, 'boom',
                                process.process, self.data)

        pop_mock.return_value.finished.assert_called_once_with(error='boom')

    @prepare_mocks
    def test_unexpected_exception(self, cli, pop_mock, process_mock):
        process_mock.side_effect = iter([RuntimeError('boom')])

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        pop_mock.return_value.finished.assert_called_once_with(
            error='Unexpected exception during processing')

    @prepare_mocks
    def test_hook_unexpected_exceptions(self, cli, pop_mock, process_mock):
        for ext in plugins_base.processing_hooks_manager():
            patcher = mock.patch.object(ext.obj, 'before_processing',
                                        side_effect=RuntimeError('boom'))
            patcher.start()
            self.addCleanup(lambda p=patcher: p.stop())

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        pop_mock.return_value.finished.assert_called_once_with(
            error='Data pre-processing failed')

    @prepare_mocks
    def test_hook_unexpected_exceptions_no_node(self, cli, pop_mock,
                                                process_mock):
        # Check that error from hooks is raised, not "not found"
        pop_mock.side_effect = iter([utils.Error('not found')])
        for ext in plugins_base.processing_hooks_manager():
            patcher = mock.patch.object(ext.obj, 'before_processing',
                                        side_effect=RuntimeError('boom'))
            patcher.start()
            self.addCleanup(lambda p=patcher: p.stop())

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        self.assertFalse(pop_mock.return_value.finished.called)

    @prepare_mocks
    def test_error_if_node_not_found_hook(self, cli, pop_mock, process_mock):
        plugins_base._NOT_FOUND_HOOK_MGR = None
        pop_mock.side_effect = iter([utils.NotFoundInCacheError('BOOM')])
        self.assertRaisesRegexp(utils.Error,
                                'Look up error: BOOM',
                                process.process, self.data)

    @prepare_mocks
    def test_node_not_found_hook_run_ok(self, cli, pop_mock, process_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        plugins_base._NOT_FOUND_HOOK_MGR = None
        pop_mock.side_effect = iter([utils.NotFoundInCacheError('BOOM')])
        with mock.patch.object(example_plugin,
                               'example_not_found_hook') as hook_mock:
            hook_mock.return_value = node_cache.NodeInfo(
                uuid=self.node.uuid,
                started_at=self.started_at)
            res = process.process(self.data)
            self.assertEqual(self.fake_result_json, res)
            hook_mock.assert_called_once_with(self.data)

    @prepare_mocks
    def test_node_not_found_hook_run_none(self, cli, pop_mock, process_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        plugins_base._NOT_FOUND_HOOK_MGR = None
        pop_mock.side_effect = iter([utils.NotFoundInCacheError('BOOM')])
        with mock.patch.object(example_plugin,
                               'example_not_found_hook') as hook_mock:
            hook_mock.return_value = None
            self.assertRaisesRegexp(utils.Error,
                                    'Node not found hook returned nothing',
                                    process.process, self.data)
            hook_mock.assert_called_once_with(self.data)

    @prepare_mocks
    def test_node_not_found_hook_exception(self, cli, pop_mock, process_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        plugins_base._NOT_FOUND_HOOK_MGR = None
        pop_mock.side_effect = iter([utils.NotFoundInCacheError('BOOM')])
        with mock.patch.object(example_plugin,
                               'example_not_found_hook') as hook_mock:
            hook_mock.side_effect = Exception('Hook Error')
            self.assertRaisesRegexp(utils.Error,
                                    'Node not found hook failed: Hook Error',
                                    process.process, self.data)
            hook_mock.assert_called_once_with(self.data)


@mock.patch.object(utils, 'spawn_n',
                   lambda f, *a: f(*a) and None)
@mock.patch.object(eventlet.greenthread, 'sleep', lambda _: None)
@mock.patch.object(example_plugin.ExampleProcessingHook, 'before_update')
@mock.patch.object(firewall, 'update_filters', autospec=True)
class TestProcessNode(BaseTest):
    def setUp(self):
        super(TestProcessNode, self).setUp()
        CONF.set_override('processing_hooks',
                          '$processing.default_processing_hooks,example',
                          'processing')
        self.validate_attempts = 5
        self.data['macs'] = self.macs  # validate_interfaces hook
        self.data['all_interfaces'] = self.data['interfaces']
        self.ports = self.all_ports
        self.node_info = node_cache.NodeInfo(uuid=self.uuid,
                                             started_at=self.started_at,
                                             node=self.node)
        self.patch_props = [
            {'path': '/properties/cpus', 'value': '2', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '1024', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '20', 'op': 'add'}
        ]  # scheduler hook
        self.new_creds = ('user', 'password')
        self.patch_credentials = [
            {'op': 'add', 'path': '/driver_info/ipmi_username',
             'value': self.new_creds[0]},
            {'op': 'add', 'path': '/driver_info/ipmi_password',
             'value': self.new_creds[1]},
        ]

        self.cli = mock.Mock()
        self.cli.node.get_boot_device.side_effect = (
            [RuntimeError()] * self.validate_attempts + [None])
        self.cli.port.create.side_effect = self.ports
        self.cli.node.update.return_value = self.node
        self.cli.node.list_ports.return_value = []

    @mock.patch.object(utils, 'get_client')
    def call(self, mock_cli):
        mock_cli.return_value = self.cli
        return process._process_node(self.node, self.data, self.node_info)

    def test_return_includes_uuid(self, filters_mock, post_hook_mock):
        ret_val = self.call()
        self.assertEqual(self.uuid, ret_val.get('uuid'))

    def test_return_includes_uuid_with_ipmi_creds(self, filters_mock,
                                                  post_hook_mock):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)
        ret_val = self.call()
        self.assertEqual(self.uuid, ret_val.get('uuid'))
        self.assertTrue(ret_val.get('ipmi_setup_credentials'))

    def test_wrong_provision_state(self, filters_mock, post_hook_mock):
        self.node.provision_state = 'active'
        self.assertRaises(utils.Error, self.call)
        self.assertFalse(post_hook_mock.called)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_ok(self, finished_mock, filters_mock, post_hook_mock):
        self.call()

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.assertFalse(self.cli.node.validate.called)

        post_hook_mock.assert_called_once_with(self.data, self.node_info,
                                               node_patches=mock.ANY,
                                               ports_patches=mock.ANY)
        finished_mock.assert_called_once_with(mock.ANY)

    def test_overwrite_disabled(self, filters_mock, post_hook_mock):
        CONF.set_override('overwrite_existing', False, 'processing')
        patch = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '2'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '1024'},
        ]

        self.call()

        self.assertCalledWithPatch(patch, self.cli.node.update)

    def test_port_failed(self, filters_mock, post_hook_mock):
        self.cli.port.create.side_effect = (
            [exceptions.Conflict()] + self.ports[1:])

        self.call()

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)

    def test_hook_patches(self, filters_mock, post_hook_mock):
        expected_node_patches = [{'path': 'foo', 'op': 'bar'}]
        expected_port_patch = [{'path': 'foo', 'op': 'baz'}]

        def fake_hook(data, node_info, node_patches, ports_patches):
            node_patches.extend(expected_node_patches)
            ports_patches.setdefault(self.macs[1],
                                     []).extend(expected_port_patch)

        post_hook_mock.side_effect = fake_hook

        self.call()

        self.assertCalledWithPatch(self.patch_props + expected_node_patches,
                                   self.cli.node.update)
        self.assertCalledWithPatch(expected_port_patch,
                                   self.cli.port.update)

    def test_set_ipmi_credentials(self, filters_mock, post_hook_mock):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)

        self.call()

        self.cli.node.update.assert_any_call(self.uuid, self.patch_credentials)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.cli.node.get_boot_device.assert_called_with(self.uuid)
        self.assertEqual(self.validate_attempts + 1,
                         self.cli.node.get_boot_device.call_count)

    def test_set_ipmi_credentials_no_address(self, filters_mock,
                                             post_hook_mock):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)
        del self.node.driver_info['ipmi_address']
        self.patch_credentials.append({'op': 'add',
                                       'path': '/driver_info/ipmi_address',
                                       'value': self.bmc_address})

        self.call()

        self.cli.node.update.assert_any_call(self.uuid, self.patch_credentials)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.cli.node.get_boot_device.assert_called_with(self.uuid)
        self.assertEqual(self.validate_attempts + 1,
                         self.cli.node.get_boot_device.call_count)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_set_ipmi_credentials_timeout(self, finished_mock,
                                          filters_mock, post_hook_mock):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)
        self.cli.node.get_boot_device.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(utils.Error, 'Failed to validate',
                                self.call)

        self.cli.node.update.assert_any_call(self.uuid, self.patch_credentials)
        self.assertEqual(2, self.cli.node.update.call_count)
        self.assertEqual(process._CREDENTIALS_WAIT_RETRIES,
                         self.cli.node.get_boot_device.call_count)
        self.assertFalse(self.cli.node.set_power_state.called)
        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Failed to validate updated IPMI credentials for node %s, '
            'node might require maintenance' % self.uuid)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_power_off_failed(self, finished_mock, filters_mock,
                              post_hook_mock):
        self.cli.node.set_power_state.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(utils.Error, 'Failed to power off',
                                self.call)

        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)
        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Failed to power off node %s, check it\'s power management'
            ' configuration: boom' % self.uuid)

    @mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
    def test_store_data(self, swift_mock, filters_mock, post_hook_mock):
        CONF.set_override('store_data', 'swift', 'processing')
        swift_conn = swift_mock.return_value
        name = 'inspector_data-%s' % self.uuid
        expected = json.dumps(self.data)

        self.call()

        swift_conn.create_object.assert_called_once_with(name, expected)
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)

    @mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
    def test_store_data_location(self, swift_mock, filters_mock,
                                 post_hook_mock):
        CONF.set_override('store_data', 'swift', 'processing')
        CONF.set_override('store_data_location', 'inspector_data_object',
                          'processing')
        swift_conn = swift_mock.return_value
        name = 'inspector_data-%s' % self.uuid
        self.patch_props.append(
            {'path': '/extra/inspector_data_object',
             'value': name,
             'op': 'add'}
        )
        expected = json.dumps(self.data)

        self.call()

        swift_conn.create_object.assert_called_once_with(name, expected)
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)
