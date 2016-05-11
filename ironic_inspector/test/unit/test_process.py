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

import base64
import copy
import functools
import json
import os
import shutil
import tempfile
import time

import eventlet
import fixtures
from ironicclient import exceptions
import mock
from oslo_config import cfg
from oslo_utils import uuidutils

from ironic_inspector.common import ironic as ir_utils
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
        self.all_ports = [mock.Mock(uuid=uuidutils.generate_uuid(),
                                    address=mac) for mac in self.macs]
        self.ports = [self.all_ports[1]]
        self.all_macs = self.macs + ['DE:AD:BE:EF:DE:AD']
        self.fake_result_json = 'node json'

        self.cli_fixture = self.useFixture(
            fixtures.MockPatchObject(ir_utils, 'get_client', autospec=True))
        self.cli = self.cli_fixture.mock.return_value


class BaseProcessTest(BaseTest):
    def setUp(self):
        super(BaseProcessTest, self).setUp()

        self.cache_fixture = self.useFixture(
            fixtures.MockPatchObject(node_cache, 'find_node', autospec=True))
        self.process_fixture = self.useFixture(
            fixtures.MockPatchObject(process, '_process_node', autospec=True))

        self.find_mock = self.cache_fixture.mock
        self.node_info = node_cache.NodeInfo(
            uuid=self.node.uuid,
            started_at=self.started_at)
        self.node_info.finished = mock.Mock()
        self.find_mock.return_value = self.node_info
        self.cli.node.get.return_value = self.node
        self.process_mock = self.process_fixture.mock
        self.process_mock.return_value = self.fake_result_json


class TestProcess(BaseProcessTest):
    def test_ok(self):
        res = process.process(self.data)

        self.assertEqual(self.fake_result_json, res)

        # Only boot interface is added by default
        self.assertEqual(['em2'], sorted(self.data['interfaces']))
        self.assertEqual([self.pxe_mac], self.data['macs'])

        self.find_mock.assert_called_once_with(bmc_address=self.bmc_address,
                                               mac=mock.ANY)
        actual_macs = self.find_mock.call_args[1]['mac']
        self.assertEqual(sorted(self.all_macs), sorted(actual_macs))
        self.cli.node.get.assert_called_once_with(self.uuid)
        self.process_mock.assert_called_once_with(
            self.node, self.data, self.node_info)

    def test_no_ipmi(self):
        del self.data['ipmi_address']
        process.process(self.data)

        self.find_mock.assert_called_once_with(bmc_address=None, mac=mock.ANY)
        actual_macs = self.find_mock.call_args[1]['mac']
        self.assertEqual(sorted(self.all_macs), sorted(actual_macs))
        self.cli.node.get.assert_called_once_with(self.uuid)
        self.process_mock.assert_called_once_with(self.node, self.data,
                                                  self.node_info)

    def test_not_found_in_cache(self):
        self.find_mock.side_effect = utils.Error('not found')

        self.assertRaisesRegexp(utils.Error,
                                'not found',
                                process.process, self.data)
        self.assertFalse(self.cli.node.get.called)
        self.assertFalse(self.process_mock.called)

    def test_not_found_in_ironic(self):
        self.cli.node.get.side_effect = exceptions.NotFound()

        self.assertRaisesRegexp(utils.Error,
                                'Node %s was not found' % self.uuid,
                                process.process, self.data)
        self.cli.node.get.assert_called_once_with(self.uuid)
        self.assertFalse(self.process_mock.called)
        self.node_info.finished.assert_called_once_with(error=mock.ANY)

    def test_already_finished(self):
        self.node_info.finished_at = time.time()
        self.assertRaisesRegexp(utils.Error, 'already finished',
                                process.process, self.data)
        self.assertFalse(self.process_mock.called)
        self.assertFalse(self.find_mock.return_value.finished.called)

    def test_expected_exception(self):
        self.process_mock.side_effect = utils.Error('boom')

        self.assertRaisesRegexp(utils.Error, 'boom',
                                process.process, self.data)

        self.node_info.finished.assert_called_once_with(error='boom')

    def test_unexpected_exception(self):
        self.process_mock.side_effect = RuntimeError('boom')

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        self.node_info.finished.assert_called_once_with(
            error='Unexpected exception RuntimeError during processing: boom')

    def test_hook_unexpected_exceptions(self):
        for ext in plugins_base.processing_hooks_manager():
            patcher = mock.patch.object(ext.obj, 'before_processing',
                                        side_effect=RuntimeError('boom'))
            patcher.start()
            self.addCleanup(lambda p=patcher: p.stop())

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        self.node_info.finished.assert_called_once_with(
            error=mock.ANY)
        error_message = self.node_info.finished.call_args[1]['error']
        self.assertIn('RuntimeError', error_message)
        self.assertIn('boom', error_message)

    def test_hook_unexpected_exceptions_no_node(self):
        # Check that error from hooks is raised, not "not found"
        self.find_mock.side_effect = utils.Error('not found')
        for ext in plugins_base.processing_hooks_manager():
            patcher = mock.patch.object(ext.obj, 'before_processing',
                                        side_effect=RuntimeError('boom'))
            patcher.start()
            self.addCleanup(lambda p=patcher: p.stop())

        self.assertRaisesRegexp(utils.Error, 'Unexpected exception',
                                process.process, self.data)

        self.assertFalse(self.node_info.finished.called)

    def test_error_if_node_not_found_hook(self):
        plugins_base._NOT_FOUND_HOOK_MGR = None
        self.find_mock.side_effect = utils.NotFoundInCacheError('BOOM')
        self.assertRaisesRegexp(utils.Error,
                                'Look up error: BOOM',
                                process.process, self.data)


@mock.patch.object(example_plugin, 'example_not_found_hook',
                   autospec=True)
class TestNodeNotFoundHook(BaseProcessTest):
    def test_node_not_found_hook_run_ok(self, hook_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        plugins_base._NOT_FOUND_HOOK_MGR = None
        self.find_mock.side_effect = utils.NotFoundInCacheError('BOOM')
        hook_mock.return_value = node_cache.NodeInfo(
            uuid=self.node.uuid,
            started_at=self.started_at)
        res = process.process(self.data)
        self.assertEqual(self.fake_result_json, res)
        hook_mock.assert_called_once_with(self.data)

    def test_node_not_found_hook_run_none(self, hook_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        plugins_base._NOT_FOUND_HOOK_MGR = None
        self.find_mock.side_effect = utils.NotFoundInCacheError('BOOM')
        hook_mock.return_value = None
        self.assertRaisesRegexp(utils.Error,
                                'Node not found hook returned nothing',
                                process.process, self.data)
        hook_mock.assert_called_once_with(self.data)

    def test_node_not_found_hook_exception(self, hook_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        plugins_base._NOT_FOUND_HOOK_MGR = None
        self.find_mock.side_effect = utils.NotFoundInCacheError('BOOM')
        hook_mock.side_effect = Exception('Hook Error')
        self.assertRaisesRegexp(utils.Error,
                                'Node not found hook failed: Hook Error',
                                process.process, self.data)
        hook_mock.assert_called_once_with(self.data)


class TestUnprocessedData(BaseProcessTest):
    @mock.patch.object(process, '_store_unprocessed_data', autospec=True)
    def test_save_unprocessed_data(self, store_mock):
        CONF.set_override('store_data', 'swift', 'processing')
        expected = copy.deepcopy(self.data)

        process.process(self.data)

        store_mock.assert_called_once_with(mock.ANY, expected)

    @mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
    def test_save_unprocessed_data_failure(self, swift_mock):
        CONF.set_override('store_data', 'swift', 'processing')
        name = 'inspector_data-%s-%s' % (
            self.uuid,
            process._UNPROCESSED_DATA_STORE_SUFFIX
        )

        swift_conn = swift_mock.return_value
        swift_conn.create_object.side_effect = utils.Error('Oops')

        res = process.process(self.data)

        # assert store failure doesn't break processing
        self.assertEqual(self.fake_result_json, res)
        swift_conn.create_object.assert_called_once_with(name, mock.ANY)


@mock.patch.object(example_plugin.ExampleProcessingHook, 'before_processing',
                   autospec=True)
class TestStoreLogs(BaseProcessTest):
    def setUp(self):
        super(TestStoreLogs, self).setUp()
        CONF.set_override('processing_hooks', 'ramdisk_error,example',
                          'processing')

        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tempdir))
        CONF.set_override('ramdisk_logs_dir', self.tempdir, 'processing')

        self.logs = b'test logs'
        self.data['logs'] = base64.b64encode(self.logs)

    def _check_contents(self):
        files = os.listdir(self.tempdir)
        self.assertEqual(1, len(files))
        filename = files[0]
        self.assertTrue(filename.startswith('bmc_%s_' % self.bmc_address),
                        '%s does not start with bmc_%s'
                        % (filename, self.bmc_address))
        with open(os.path.join(self.tempdir, filename), 'rb') as fp:
            self.assertEqual(self.logs, fp.read())

    def test_store_on_preprocess_failure(self, hook_mock):
        hook_mock.side_effect = Exception('Hook Error')
        self.assertRaises(utils.Error, process.process, self.data)
        self._check_contents()

    def test_store_on_process_failure(self, hook_mock):
        self.process_mock.side_effect = utils.Error('boom')
        self.assertRaises(utils.Error, process.process, self.data)
        self._check_contents()

    def test_store_on_unexpected_process_failure(self, hook_mock):
        self.process_mock.side_effect = RuntimeError('boom')
        self.assertRaises(utils.Error, process.process, self.data)
        self._check_contents()

    def test_store_on_ramdisk_error(self, hook_mock):
        self.data['error'] = 'boom'
        self.assertRaises(utils.Error, process.process, self.data)
        self._check_contents()

    def test_store_find_node_error(self, hook_mock):
        self.cli.node.get.side_effect = exceptions.NotFound('boom')
        self.assertRaises(utils.Error, process.process, self.data)
        self._check_contents()

    def test_no_error_no_logs(self, hook_mock):
        process.process(self.data)
        self.assertEqual([], os.listdir(self.tempdir))

    def test_logs_disabled(self, hook_mock):
        CONF.set_override('ramdisk_logs_dir', None, 'processing')
        hook_mock.side_effect = Exception('Hook Error')
        self.assertRaises(utils.Error, process.process, self.data)
        self.assertEqual([], os.listdir(self.tempdir))

    def test_always_store_logs(self, hook_mock):
        CONF.set_override('always_store_ramdisk_logs', True, 'processing')
        process.process(self.data)
        self._check_contents()

    @mock.patch.object(process.LOG, 'exception', autospec=True)
    def test_failure_to_write(self, log_mock, hook_mock):
        CONF.set_override('always_store_ramdisk_logs', True, 'processing')
        CONF.set_override('ramdisk_logs_dir', '/I/cannot/write/here',
                          'processing')
        process.process(self.data)
        self.assertEqual([], os.listdir(self.tempdir))
        self.assertTrue(log_mock.called)

    def test_directory_is_created(self, hook_mock):
        shutil.rmtree(self.tempdir)
        self.data['error'] = 'boom'
        self.assertRaises(utils.Error, process.process, self.data)
        self._check_contents()


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

        self.cli.node.get_boot_device.side_effect = (
            [RuntimeError()] * self.validate_attempts + [None])
        self.cli.port.create.side_effect = self.ports
        self.cli.node.update.return_value = self.node
        self.cli.node.list_ports.return_value = []

        self.useFixture(fixtures.MockPatchObject(
            firewall, 'update_filters', autospec=True))

        self.useFixture(fixtures.MockPatchObject(
            eventlet.greenthread, 'sleep', autospec=True))

    def test_return_includes_uuid(self):
        ret_val = process._process_node(self.node, self.data, self.node_info)
        self.assertEqual(self.uuid, ret_val.get('uuid'))

    def test_return_includes_uuid_with_ipmi_creds(self):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)
        ret_val = process._process_node(self.node, self.data, self.node_info)
        self.assertEqual(self.uuid, ret_val.get('uuid'))
        self.assertTrue(ret_val.get('ipmi_setup_credentials'))

    @mock.patch.object(example_plugin.ExampleProcessingHook, 'before_update')
    def test_wrong_provision_state(self, post_hook_mock):
        self.node.provision_state = 'active'

        self.assertRaises(utils.Error, process._process_node,
                          self.node, self.data, self.node_info)
        self.assertFalse(post_hook_mock.called)

    @mock.patch.object(example_plugin.ExampleProcessingHook, 'before_update')
    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_ok(self, finished_mock, post_hook_mock):
        process._process_node(self.node, self.data, self.node_info)

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.assertFalse(self.cli.node.validate.called)

        post_hook_mock.assert_called_once_with(self.data, self.node_info)
        finished_mock.assert_called_once_with(mock.ANY)

    def test_overwrite_disabled(self):
        CONF.set_override('overwrite_existing', False, 'processing')
        patch = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '2'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '1024'},
        ]

        process._process_node(self.node, self.data, self.node_info)

        self.assertCalledWithPatch(patch, self.cli.node.update)

    def test_port_failed(self):
        self.cli.port.create.side_effect = (
            [exceptions.Conflict()] + self.ports[1:])

        process._process_node(self.node, self.data, self.node_info)

        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[0])
        self.cli.port.create.assert_any_call(node_uuid=self.uuid,
                                             address=self.macs[1])
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)

    def test_set_ipmi_credentials(self):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)

        process._process_node(self.node, self.data, self.node_info)

        self.cli.node.update.assert_any_call(self.uuid, self.patch_credentials)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.cli.node.get_boot_device.assert_called_with(self.uuid)
        self.assertEqual(self.validate_attempts + 1,
                         self.cli.node.get_boot_device.call_count)

    def test_set_ipmi_credentials_no_address(self):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)
        del self.node.driver_info['ipmi_address']
        self.patch_credentials.append({'op': 'add',
                                       'path': '/driver_info/ipmi_address',
                                       'value': self.bmc_address})

        process._process_node(self.node, self.data, self.node_info)

        self.cli.node.update.assert_any_call(self.uuid, self.patch_credentials)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.cli.node.get_boot_device.assert_called_with(self.uuid)
        self.assertEqual(self.validate_attempts + 1,
                         self.cli.node.get_boot_device.call_count)

    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_set_ipmi_credentials_timeout(self, finished_mock):
        self.node_info.set_option('new_ipmi_credentials', self.new_creds)
        self.cli.node.get_boot_device.side_effect = RuntimeError('boom')

        process._process_node(self.node, self.data, self.node_info)

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
    def test_power_off_failed(self, finished_mock):
        self.cli.node.set_power_state.side_effect = RuntimeError('boom')

        process._process_node(self.node, self.data, self.node_info)

        self.cli.node.set_power_state.assert_called_once_with(self.uuid, 'off')
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)
        finished_mock.assert_called_once_with(
            mock.ANY,
            error='Failed to power off node %s, check its power '
                  'management configuration: boom' % self.uuid
        )

    @mock.patch.object(example_plugin.ExampleProcessingHook, 'before_update')
    @mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
    def test_power_off_enroll_state(self, finished_mock, post_hook_mock):
        self.node.provision_state = 'enroll'
        self.node_info.node = mock.Mock(return_value=self.node)

        process._process_node(self.node, self.data, self.node_info)

        self.assertTrue(post_hook_mock.called)
        self.assertTrue(self.cli.node.set_power_state.called)
        finished_mock.assert_called_once_with(self.node_info)

    @mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
    def test_store_data(self, swift_mock):
        CONF.set_override('store_data', 'swift', 'processing')
        swift_conn = swift_mock.return_value
        name = 'inspector_data-%s' % self.uuid
        expected = self.data

        process._process_node(self.node, self.data, self.node_info)

        swift_conn.create_object.assert_called_once_with(name, mock.ANY)
        self.assertEqual(expected,
                         json.loads(swift_conn.create_object.call_args[0][1]))
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)

    @mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
    def test_store_data_no_logs(self, swift_mock):
        CONF.set_override('store_data', 'swift', 'processing')
        swift_conn = swift_mock.return_value
        name = 'inspector_data-%s' % self.uuid
        expected = self.data.copy()
        self.data['logs'] = 'something'

        process._process_node(self.node, self.data, self.node_info)

        swift_conn.create_object.assert_called_once_with(name, mock.ANY)
        self.assertEqual(expected,
                         json.loads(swift_conn.create_object.call_args[0][1]))
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)

    @mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
    def test_store_data_location(self, swift_mock):
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
        expected = self.data

        process._process_node(self.node, self.data, self.node_info)

        swift_conn.create_object.assert_called_once_with(name, mock.ANY)
        self.assertEqual(expected,
                         json.loads(swift_conn.create_object.call_args[0][1]))
        self.assertCalledWithPatch(self.patch_props, self.cli.node.update)


@mock.patch.object(process, '_reapply', autospec=True)
@mock.patch.object(node_cache, 'get_node', autospec=True)
class TestReapply(BaseTest):
    def prepare_mocks(func):
        @functools.wraps(func)
        def wrapper(self, pop_mock, *args, **kw):
            pop_mock.return_value = node_cache.NodeInfo(
                uuid=self.node.uuid,
                started_at=self.started_at)
            pop_mock.return_value.finished = mock.Mock()
            pop_mock.return_value.acquire_lock = mock.Mock()
            return func(self, pop_mock, *args, **kw)

        return wrapper

    def setUp(self):
        super(TestReapply, self).setUp()
        CONF.set_override('store_data', 'swift', 'processing')

    @prepare_mocks
    def test_ok(self, pop_mock, reapply_mock):
        process.reapply(self.uuid)
        pop_mock.assert_called_once_with(self.uuid, locked=False)
        pop_mock.return_value.acquire_lock.assert_called_once_with(
            blocking=False
        )

        reapply_mock.assert_called_once_with(pop_mock.return_value)

    @prepare_mocks
    def test_locking_failed(self, pop_mock, reapply_mock):
        pop_mock.return_value.acquire_lock.return_value = False
        exc = utils.Error('Node locked, please, try again later')

        with self.assertRaises(type(exc)) as cm:
            process.reapply(self.uuid)

        self.assertEqual(str(exc), str(cm.exception))

        pop_mock.assert_called_once_with(self.uuid, locked=False)
        pop_mock.return_value.acquire_lock.assert_called_once_with(
            blocking=False
        )


@mock.patch.object(example_plugin.ExampleProcessingHook, 'before_update')
@mock.patch.object(process.rules, 'apply', autospec=True)
@mock.patch.object(process.swift, 'SwiftAPI', autospec=True)
@mock.patch.object(node_cache.NodeInfo, 'finished', autospec=True)
@mock.patch.object(node_cache.NodeInfo, 'release_lock', autospec=True)
class TestReapplyNode(BaseTest):
    def setUp(self):
        super(TestReapplyNode, self).setUp()
        CONF.set_override('processing_hooks',
                          '$processing.default_processing_hooks,example',
                          'processing')
        CONF.set_override('store_data', 'swift', 'processing')
        self.data['macs'] = self.macs
        self.data['all_interfaces'] = self.data['interfaces']
        self.ports = self.all_ports
        self.node_info = node_cache.NodeInfo(uuid=self.uuid,
                                             started_at=self.started_at,
                                             node=self.node)
        self.node_info.invalidate_cache = mock.Mock()
        self.new_creds = ('user', 'password')

        self.cli.port.create.side_effect = self.ports
        self.cli.node.update.return_value = self.node
        self.cli.node.list_ports.return_value = []

    def call(self):
        process._reapply(self.node_info)
        # make sure node_info lock is released after a call
        self.node_info.release_lock.assert_called_once_with(self.node_info)

    def prepare_mocks(fn):
        @functools.wraps(fn)
        def wrapper(self, release_mock, finished_mock, swift_mock,
                    *args, **kw):
            finished_mock.side_effect = lambda *a, **kw: \
                release_mock(self.node_info)
            swift_client_mock = swift_mock.return_value
            fn(self, finished_mock, swift_client_mock, *args, **kw)
        return wrapper

    @prepare_mocks
    def test_ok(self, finished_mock, swift_mock, apply_mock,
                post_hook_mock):
        swift_name = 'inspector_data-%s' % self.uuid
        swift_mock.get_object.return_value = json.dumps(self.data)

        with mock.patch.object(process.LOG, 'error',
                               autospec=True) as log_mock:
            self.call()

        # no failures logged
        self.assertFalse(log_mock.called)

        post_hook_mock.assert_called_once_with(mock.ANY, self.node_info)
        swift_mock.create_object.assert_called_once_with(swift_name,
                                                         mock.ANY)
        swifted_data = json.loads(swift_mock.create_object.call_args[0][1])

        self.node_info.invalidate_cache.assert_called_once_with()
        apply_mock.assert_called_once_with(self.node_info, swifted_data)

        # assert no power operations were performed
        self.assertFalse(self.cli.node.set_power_state.called)
        finished_mock.assert_called_once_with(self.node_info)

        # asserting validate_interfaces was called
        self.assertEqual({'em2': self.data['interfaces']['em2']},
                         swifted_data['interfaces'])
        self.assertEqual([self.pxe_mac], swifted_data['macs'])

        # assert ports were created with whatever there was left
        # behind validate_interfaces
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid,
            address=swifted_data['macs'][0]
        )

    @prepare_mocks
    def test_get_incomming_data_exception(self, finished_mock,
                                          swift_mock, apply_mock,
                                          post_hook_mock, ):
        exc = Exception('Oops')
        swift_mock.get_object.side_effect = exc
        with mock.patch.object(process.LOG, 'exception',
                               autospec=True) as log_mock:
            self.call()

        log_mock.assert_called_once_with('Encountered exception '
                                         'while fetching stored '
                                         'introspection data',
                                         node_info=self.node_info)

        self.assertFalse(swift_mock.create_object.called)
        self.assertFalse(apply_mock.called)
        self.assertFalse(post_hook_mock.called)
        self.assertFalse(finished_mock.called)

    @prepare_mocks
    def test_prehook_failure(self, finished_mock, swift_mock,
                             apply_mock, post_hook_mock, ):
        CONF.set_override('processing_hooks', 'example',
                          'processing')
        plugins_base._HOOKS_MGR = None

        exc = Exception('Failed.')
        swift_mock.get_object.return_value = json.dumps(self.data)

        with mock.patch.object(example_plugin.ExampleProcessingHook,
                               'before_processing') as before_processing_mock:
            before_processing_mock.side_effect = exc
            with mock.patch.object(process.LOG, 'error',
                                   autospec=True) as log_mock:
                self.call()

        exc_failure = ('Unexpected exception %(exc_class)s during '
                       'preprocessing in hook example: %(error)s' %
                       {'exc_class': type(exc).__name__, 'error':
                        exc})
        log_mock.assert_called_once_with('Pre-processing failures '
                                         'detected reapplying '
                                         'introspection on stored '
                                         'data:\n%s', exc_failure,
                                         node_info=self.node_info)
        finished_mock.assert_called_once_with(self.node_info,
                                              error=exc_failure)
        # assert _reapply ended having detected the failure
        self.assertFalse(swift_mock.create_object.called)
        self.assertFalse(apply_mock.called)
        self.assertFalse(post_hook_mock.called)

    @prepare_mocks
    def test_generic_exception_creating_ports(self, finished_mock,
                                              swift_mock, apply_mock,
                                              post_hook_mock):
        swift_mock.get_object.return_value = json.dumps(self.data)
        exc = Exception('Oops')
        self.cli.port.create.side_effect = exc

        with mock.patch.object(process.LOG, 'exception') as log_mock:
            self.call()

        log_mock.assert_called_once_with('Encountered exception reapplying'
                                         ' introspection on stored data',
                                         node_info=self.node_info,
                                         data=mock.ANY)
        finished_mock.assert_called_once_with(self.node_info, error=str(exc))
        self.assertFalse(swift_mock.create_object.called)
        self.assertFalse(apply_mock.called)
        self.assertFalse(post_hook_mock.called)
