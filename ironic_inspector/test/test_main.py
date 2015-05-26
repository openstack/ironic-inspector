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

import json
import unittest

import eventlet
import mock
from oslo_utils import uuidutils

from ironic_inspector import firewall
from ironic_inspector import introspect
from ironic_inspector import main
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector.plugins import example as example_plugin
from ironic_inspector import process
from ironic_inspector.test import base as test_base
from ironic_inspector import utils
from oslo_config import cfg

CONF = cfg.CONF


class TestApi(test_base.BaseTest):
    def setUp(self):
        super(TestApi, self).setUp()
        main.app.config['TESTING'] = True
        self.app = main.app.test_client()
        CONF.set_override('authenticate', False)
        self.uuid = uuidutils.generate_uuid()

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_no_authentication(self, introspect_mock):
        CONF.set_override('authenticate', False)
        res = self.app.post('/v1/introspection/%s' % self.uuid)
        self.assertEqual(202, res.status_code)
        introspect_mock.assert_called_once_with(self.uuid,
                                                new_ipmi_credentials=None)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_set_ipmi_credentials(self, introspect_mock):
        CONF.set_override('authenticate', False)
        res = self.app.post('/v1/introspection/%s?new_ipmi_username=user&'
                            'new_ipmi_password=password' % self.uuid)
        self.assertEqual(202, res.status_code)
        introspect_mock.assert_called_once_with(
            self.uuid,
            new_ipmi_credentials=('user', 'password'))

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_set_ipmi_credentials_no_user(self, introspect_mock):
        CONF.set_override('authenticate', False)
        res = self.app.post('/v1/introspection/%s?'
                            'new_ipmi_password=password' % self.uuid)
        self.assertEqual(202, res.status_code)
        introspect_mock.assert_called_once_with(
            self.uuid,
            new_ipmi_credentials=(None, 'password'))

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_intospect_failed(self, introspect_mock):
        introspect_mock.side_effect = utils.Error("boom")
        res = self.app.post('/v1/introspection/%s' % self.uuid)
        self.assertEqual(400, res.status_code)
        self.assertEqual(b"boom", res.data)
        introspect_mock.assert_called_once_with(
            self.uuid,
            new_ipmi_credentials=None)

    @mock.patch.object(utils, 'check_auth', autospec=True)
    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_failed_authentication(self, introspect_mock,
                                              auth_mock):
        CONF.set_override('authenticate', True)
        auth_mock.side_effect = utils.Error('Boom', code=403)
        res = self.app.post('/v1/introspection/%s' % self.uuid,
                            headers={'X-Auth-Token': 'token'})
        self.assertEqual(403, res.status_code)
        self.assertFalse(introspect_mock.called)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_invalid_uuid(self, introspect_mock):
        uuid_dummy = 'uuid1'
        res = self.app.post('/v1/introspection/%s' % uuid_dummy)
        self.assertEqual(400, res.status_code)

    @mock.patch.object(process, 'process', autospec=True)
    def test_continue(self, process_mock):
        # should be ignored
        CONF.set_override('authenticate', True)
        process_mock.return_value = [42]
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(200, res.status_code)
        process_mock.assert_called_once_with("JSON")
        self.assertEqual(b'[42]', res.data)

    @mock.patch.object(process, 'process', autospec=True)
    def test_continue_failed(self, process_mock):
        process_mock.side_effect = utils.Error("boom")
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(400, res.status_code)
        process_mock.assert_called_once_with("JSON")
        self.assertEqual(b'boom', res.data)

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_get_introspection_in_progress(self, get_mock):
        get_mock.return_value = node_cache.NodeInfo(uuid=self.uuid,
                                                    started_at=42.0)
        res = self.app.get('/v1/introspection/%s' % self.uuid)
        self.assertEqual(200, res.status_code)
        self.assertEqual({'finished': False, 'error': None},
                         json.loads(res.data.decode('utf-8')))

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_get_introspection_finished(self, get_mock):
        get_mock.return_value = node_cache.NodeInfo(uuid=self.uuid,
                                                    started_at=42.0,
                                                    finished_at=100.1,
                                                    error='boom')
        res = self.app.get('/v1/introspection/%s' % self.uuid)
        self.assertEqual(200, res.status_code)
        self.assertEqual({'finished': True, 'error': 'boom'},
                         json.loads(res.data.decode('utf-8')))


@mock.patch.object(eventlet.greenthread, 'sleep', autospec=True)
@mock.patch.object(utils, 'get_client')
class TestCheckIronicAvailable(test_base.BaseTest):
    def test_ok(self, client_mock, sleep_mock):
        main.check_ironic_available()
        client_mock.return_value.driver.list.assert_called_once_with()
        self.assertFalse(sleep_mock.called)

    def test_2_attempts(self, client_mock, sleep_mock):
        cli = mock.Mock()
        client_mock.side_effect = [Exception(), cli]
        main.check_ironic_available()
        self.assertEqual(2, client_mock.call_count)
        cli.driver.list.assert_called_once_with()
        sleep_mock.assert_called_once_with(
            CONF.ironic.ironic_retry_period)

    def test_failed(self, client_mock, sleep_mock):
        attempts = CONF.ironic.ironic_retry_attempts
        client_mock.side_effect = RuntimeError()
        self.assertRaises(RuntimeError, main.check_ironic_available)
        self.assertEqual(1 + attempts, client_mock.call_count)
        self.assertEqual(attempts, sleep_mock.call_count)


class TestPlugins(unittest.TestCase):
    @mock.patch.object(example_plugin.ExampleProcessingHook,
                       'before_processing', autospec=True)
    @mock.patch.object(example_plugin.ExampleProcessingHook,
                       'before_update', autospec=True)
    def test_hook(self, mock_post, mock_pre):
        plugins_base._HOOKS_MGR = None
        CONF.set_override('processing_hooks', 'example', 'processing')
        mgr = plugins_base.processing_hooks_manager()
        mgr.map_method('before_processing', 'node_info')
        mock_pre.assert_called_once_with(mock.ANY, 'node_info')
        mgr.map_method('before_update', 'node', ['port'], 'node_info')
        mock_post.assert_called_once_with(mock.ANY, 'node', ['port'],
                                          'node_info')

    def test_manager_is_cached(self):
        self.assertIs(plugins_base.processing_hooks_manager(),
                      plugins_base.processing_hooks_manager())


@mock.patch.object(eventlet.greenthread, 'spawn_n')
@mock.patch.object(firewall, 'init')
@mock.patch.object(utils, 'add_auth_middleware')
@mock.patch.object(utils, 'get_client')
@mock.patch.object(node_cache, 'init')
class TestInit(test_base.BaseTest):
    def test_ok(self, mock_node_cache, mock_get_client, mock_auth,
                mock_firewall, mock_spawn_n):
        CONF.set_override('authenticate', True)
        main.init()
        mock_auth.assert_called_once_with(main.app)
        mock_node_cache.assert_called_once_with()
        mock_firewall.assert_called_once_with()

        spawn_n_expected_args = [
            (main.periodic_update, CONF.firewall.firewall_update_period),
            (main.periodic_clean_up, CONF.clean_up_period)]
        spawn_n_call_args_list = mock_spawn_n.call_args_list

        for (args, call) in zip(spawn_n_expected_args,
                                spawn_n_call_args_list):
            self.assertEqual(args, call[0])

    def test_init_without_authenticate(self, mock_node_cache, mock_get_client,
                                       mock_auth, mock_firewall, mock_spawn_n):
        CONF.set_override('authenticate', False)
        main.init()
        self.assertFalse(mock_auth.called)

    def test_init_without_manage_firewall(self, mock_node_cache,
                                          mock_get_client, mock_auth,
                                          mock_firewall, mock_spawn_n):
        CONF.set_override('manage_firewall', False, 'firewall')
        main.init()
        self.assertFalse(mock_firewall.called)
        spawn_n_expected_args = [
            (main.periodic_clean_up, CONF.clean_up_period)]
        spawn_n_call_args_list = mock_spawn_n.call_args_list
        for (args, call) in zip(spawn_n_expected_args,
                                spawn_n_call_args_list):
            self.assertEqual(args, call[0])

    def test_init_with_timeout_0(self, mock_node_cache, mock_get_client,
                                 mock_auth, mock_firewall, mock_spawn_n):
        CONF.set_override('timeout', 0)
        main.init()
        spawn_n_expected_args = [
            (main.periodic_update, CONF.firewall.firewall_update_period)]
        spawn_n_call_args_list = mock_spawn_n.call_args_list

        for (args, call) in zip(spawn_n_expected_args,
                                spawn_n_call_args_list):
            self.assertEqual(args, call[0])

    @mock.patch.object(main.LOG, 'critical')
    def test_init_failed_processing_hook(self, mock_log, mock_node_cache,
                                         mock_get_client, mock_auth,
                                         mock_firewall, mock_spawn_n):
        CONF.set_override('processing_hooks', 'foo!', 'processing')
        plugins_base._HOOKS_MGR = None

        self.assertRaises(SystemExit, main.init)
        mock_log.assert_called_once_with(mock.ANY, "'foo!'")
