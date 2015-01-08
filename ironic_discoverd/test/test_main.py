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
from ironicclient import exceptions
from keystoneclient import exceptions as keystone_exc
import mock

from ironic_discoverd import conf
from ironic_discoverd import discover
from ironic_discoverd import main
from ironic_discoverd import node_cache
from ironic_discoverd.plugins import base as plugins_base
from ironic_discoverd.plugins import example as example_plugin
from ironic_discoverd import process
from ironic_discoverd.test import base as test_base
from ironic_discoverd import utils


class TestApi(test_base.BaseTest):
    def setUp(self):
        super(TestApi, self).setUp()
        main.app.config['TESTING'] = True
        self.app = main.app.test_client()
        conf.CONF.set('discoverd', 'authenticate', 'false')

    @mock.patch.object(discover, 'introspect', autospec=True)
    def test_introspect_no_authentication(self, discover_mock):
        conf.CONF.set('discoverd', 'authenticate', 'false')
        res = self.app.post('/v1/introspection/uuid1')
        self.assertEqual(202, res.status_code)
        discover_mock.assert_called_once_with("uuid1")

    @mock.patch.object(discover, 'introspect', autospec=True)
    def test_intospect_failed(self, discover_mock):
        discover_mock.side_effect = utils.DiscoveryFailed("boom")
        res = self.app.post('/v1/introspection/uuid1')
        self.assertEqual(400, res.status_code)
        self.assertEqual(b"boom", res.data)
        discover_mock.assert_called_once_with("uuid1")

    @mock.patch.object(discover, 'introspect', autospec=True)
    def test_discover_missing_authentication(self, discover_mock):
        conf.CONF.set('discoverd', 'authenticate', 'true')
        res = self.app.post('/v1/introspection/uuid1')
        self.assertEqual(401, res.status_code)
        self.assertFalse(discover_mock.called)

    @mock.patch.object(utils, 'check_is_admin', autospec=True)
    @mock.patch.object(discover, 'introspect', autospec=True)
    def test_discover_failed_authentication(self, discover_mock,
                                            keystone_mock):
        conf.CONF.set('discoverd', 'authenticate', 'true')
        keystone_mock.side_effect = keystone_exc.Unauthorized()
        res = self.app.post('/v1/introspection/uuid1',
                            headers={'X-Auth-Token': 'token'})
        self.assertEqual(403, res.status_code)
        self.assertFalse(discover_mock.called)
        keystone_mock.assert_called_once_with(token='token')

    @mock.patch.object(discover, 'introspect', autospec=True)
    def test_discover(self, discover_mock):
        res = self.app.post('/v1/discover', data='["uuid1"]')
        self.assertEqual(202, res.status_code)
        discover_mock.assert_called_once_with("uuid1")

    @mock.patch.object(process, 'process', autospec=True)
    def test_continue(self, process_mock):
        conf.CONF.set('discoverd', 'authenticate', 'true')  # should be ignored
        process_mock.return_value = [42]
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(200, res.status_code)
        process_mock.assert_called_once_with("JSON")
        self.assertEqual(b'[42]', res.data)

    @mock.patch.object(process, 'process', autospec=True)
    def test_continue_failed(self, process_mock):
        process_mock.side_effect = utils.DiscoveryFailed("boom")
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(400, res.status_code)
        process_mock.assert_called_once_with("JSON")
        self.assertEqual(b'boom', res.data)

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_get_introspection_in_progress(self, get_mock):
        get_mock.return_value = node_cache.NodeInfo(uuid='uuid',
                                                    started_at=42.0)
        res = self.app.get('/v1/introspection/uuid')
        self.assertEqual(200, res.status_code)
        self.assertEqual({'finished': False, 'error': None},
                         json.loads(res.data.decode('utf-8')))

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_get_introspection_finished(self, get_mock):
        get_mock.return_value = node_cache.NodeInfo(uuid='uuid',
                                                    started_at=42.0,
                                                    finished_at=100.1,
                                                    error='boom')
        res = self.app.get('/v1/introspection/uuid')
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
            conf.getint('discoverd', 'ironic_retry_period'))

    def test_failed(self, client_mock, sleep_mock):
        attempts = conf.getint('discoverd', 'ironic_retry_attempts')
        client_mock.side_effect = RuntimeError()
        self.assertRaises(RuntimeError, main.check_ironic_available)
        self.assertEqual(1 + attempts, client_mock.call_count)
        self.assertEqual(attempts, sleep_mock.call_count)


class TestPlugins(unittest.TestCase):
    @mock.patch.object(example_plugin.ExampleProcessingHook, 'pre_discover',
                       autospec=True)
    @mock.patch.object(example_plugin.ExampleProcessingHook, 'post_discover',
                       autospec=True)
    def test_hook(self, mock_post, mock_pre):
        plugins_base._HOOKS_MGR = None
        conf.CONF.set('discoverd', 'processing_hooks', 'example')
        mgr = plugins_base.processing_hooks_manager()
        mgr.map_method('pre_discover', 'node_info')
        mock_pre.assert_called_once_with(mock.ANY, 'node_info')
        mgr.map_method('post_discover', 'node', ['port'], 'node_info')
        mock_post.assert_called_once_with(mock.ANY, 'node', ['port'],
                                          'node_info')

    def test_manager_is_cached(self):
        self.assertIs(plugins_base.processing_hooks_manager(),
                      plugins_base.processing_hooks_manager())


@mock.patch.object(eventlet.greenthread, 'sleep', lambda _: None)
class TestUtils(unittest.TestCase):
    def test_retry_on_conflict(self):
        call = mock.Mock()
        call.side_effect = ([exceptions.Conflict()] * (utils.RETRY_COUNT - 1)
                            + [mock.sentinel.result])
        res = utils.retry_on_conflict(call, 1, 2, x=3)
        self.assertEqual(mock.sentinel.result, res)
        call.assert_called_with(1, 2, x=3)
        self.assertEqual(utils.RETRY_COUNT, call.call_count)

    def test_retry_on_conflict_fail(self):
        call = mock.Mock()
        call.side_effect = ([exceptions.Conflict()] * (utils.RETRY_COUNT + 1)
                            + [mock.sentinel.result])
        self.assertRaises(exceptions.Conflict, utils.retry_on_conflict,
                          call, 1, 2, x=3)
        call.assert_called_with(1, 2, x=3)
        self.assertEqual(utils.RETRY_COUNT, call.call_count)
