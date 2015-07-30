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
import ssl
import sys
import unittest

import mock
from oslo_utils import uuidutils

from ironic_inspector import db
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


def _get_error(res):
    return json.loads(res.data.decode('utf-8'))['error']['message']


class BaseAPITest(test_base.BaseTest):
    def setUp(self):
        super(BaseAPITest, self).setUp()
        main.app.config['TESTING'] = True
        self.app = main.app.test_client()
        CONF.set_override('auth_strategy', 'noauth')
        self.uuid = uuidutils.generate_uuid()


class TestApiIntrospect(BaseAPITest):
    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_no_authentication(self, introspect_mock):
        CONF.set_override('auth_strategy', 'noauth')
        res = self.app.post('/v1/introspection/%s' % self.uuid)
        self.assertEqual(202, res.status_code)
        introspect_mock.assert_called_once_with(self.uuid,
                                                new_ipmi_credentials=None,
                                                token=None)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_set_ipmi_credentials(self, introspect_mock):
        res = self.app.post('/v1/introspection/%s?new_ipmi_username=user&'
                            'new_ipmi_password=password' % self.uuid)
        self.assertEqual(202, res.status_code)
        introspect_mock.assert_called_once_with(
            self.uuid,
            new_ipmi_credentials=('user', 'password'),
            token=None)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_set_ipmi_credentials_no_user(self, introspect_mock):
        res = self.app.post('/v1/introspection/%s?'
                            'new_ipmi_password=password' % self.uuid)
        self.assertEqual(202, res.status_code)
        introspect_mock.assert_called_once_with(
            self.uuid,
            new_ipmi_credentials=(None, 'password'),
            token=None)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_intospect_failed(self, introspect_mock):
        introspect_mock.side_effect = iter([utils.Error("boom")])
        res = self.app.post('/v1/introspection/%s' % self.uuid)
        self.assertEqual(400, res.status_code)
        self.assertEqual(
            'boom',
            json.loads(res.data.decode('utf-8'))['error']['message'])
        introspect_mock.assert_called_once_with(
            self.uuid,
            new_ipmi_credentials=None,
            token=None)

    @mock.patch.object(utils, 'check_auth', autospec=True)
    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_failed_authentication(self, introspect_mock,
                                              auth_mock):
        CONF.set_override('auth_strategy', 'keystone')
        auth_mock.side_effect = iter([utils.Error('Boom', code=403)])
        res = self.app.post('/v1/introspection/%s' % self.uuid,
                            headers={'X-Auth-Token': 'token'})
        self.assertEqual(403, res.status_code)
        self.assertFalse(introspect_mock.called)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_invalid_uuid(self, introspect_mock):
        uuid_dummy = 'uuid1'
        res = self.app.post('/v1/introspection/%s' % uuid_dummy)
        self.assertEqual(400, res.status_code)


class TestApiContinue(BaseAPITest):
    @mock.patch.object(process, 'process', autospec=True)
    def test_continue(self, process_mock):
        # should be ignored
        CONF.set_override('auth_strategy', 'keystone')
        process_mock.return_value = [42]
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(200, res.status_code)
        process_mock.assert_called_once_with("JSON")
        self.assertEqual(b'[42]', res.data)

    @mock.patch.object(process, 'process', autospec=True)
    def test_continue_failed(self, process_mock):
        process_mock.side_effect = iter([utils.Error("boom")])
        res = self.app.post('/v1/continue', data='"JSON"')
        self.assertEqual(400, res.status_code)
        process_mock.assert_called_once_with("JSON")
        self.assertEqual('boom', _get_error(res))


class TestApiGetStatus(BaseAPITest):
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


class TestApiMisc(BaseAPITest):
    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_404_expected(self, get_mock):
        get_mock.side_effect = iter([utils.Error('boom', code=404)])
        res = self.app.get('/v1/introspection/%s' % self.uuid)
        self.assertEqual(404, res.status_code)
        self.assertEqual('boom', _get_error(res))

    def test_404_unexpected(self):
        res = self.app.get('/v42')
        self.assertEqual(404, res.status_code)
        self.assertIn('not found', _get_error(res).lower())

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_500_with_debug(self, get_mock):
        CONF.set_override('debug', True)
        get_mock.side_effect = iter([RuntimeError('boom')])
        res = self.app.get('/v1/introspection/%s' % self.uuid)
        self.assertEqual(500, res.status_code)
        self.assertEqual('Internal server error (RuntimeError): boom',
                         _get_error(res))

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_500_without_debug(self, get_mock):
        CONF.set_override('debug', False)
        get_mock.side_effect = iter([RuntimeError('boom')])
        res = self.app.get('/v1/introspection/%s' % self.uuid)
        self.assertEqual(500, res.status_code)
        self.assertEqual('Internal server error',
                         _get_error(res))


class TestApiVersions(BaseAPITest):
    def _check_version_present(self, res):
        self.assertEqual('%d.%d' % main.MINIMUM_API_VERSION,
                         res.headers.get(main._MIN_VERSION_HEADER))
        self.assertEqual('%d.%d' % main.CURRENT_API_VERSION,
                         res.headers.get(main._MAX_VERSION_HEADER))

    def test_root_endpoints(self):
        for endpoint in '/', '/v1':
            res = self.app.get(endpoint)
            self.assertEqual(200, res.status_code)
            self._check_version_present(res)

    def test_404_unexpected(self):
        # API version on unknown pages
        self._check_version_present(self.app.get('/v1/foobar'))

    @mock.patch.object(node_cache, 'get_node', autospec=True)
    def test_usual_requests(self, get_mock):
        get_mock.return_value = node_cache.NodeInfo(uuid=self.uuid,
                                                    started_at=42.0)
        # Successfull
        self._check_version_present(
            self.app.post('/v1/introspection/%s' % self.uuid))
        # With error
        self._check_version_present(
            self.app.post('/v1/introspection/foobar'))

    def test_request_correct_version(self):
        headers = {main._VERSION_HEADER:
                   main._format_version(main.CURRENT_API_VERSION)}
        self._check_version_present(self.app.get('/', headers=headers))

    def test_request_unsupported_version(self):
        bad_version = (main.CURRENT_API_VERSION[0],
                       main.CURRENT_API_VERSION[1] + 1)
        headers = {main._VERSION_HEADER:
                   main._format_version(bad_version)}
        res = self.app.get('/', headers=headers)
        self._check_version_present(res)
        self.assertEqual(406, res.status_code)
        error = _get_error(res)
        self.assertIn('%d.%d' % bad_version, error)
        self.assertIn('%d.%d' % main.MINIMUM_API_VERSION, error)
        self.assertIn('%d.%d' % main.CURRENT_API_VERSION, error)


class TestPlugins(unittest.TestCase):
    @mock.patch.object(example_plugin.ExampleProcessingHook,
                       'before_processing', autospec=True)
    @mock.patch.object(example_plugin.ExampleProcessingHook,
                       'before_update', autospec=True)
    def test_hook(self, mock_post, mock_pre):
        plugins_base._HOOKS_MGR = None
        CONF.set_override('processing_hooks', 'example', 'processing')
        mgr = plugins_base.processing_hooks_manager()
        mgr.map_method('before_processing', 'introspection_data')
        mock_pre.assert_called_once_with(mock.ANY, 'introspection_data')
        mgr.map_method('before_update', 'node_info', {}, [], {})
        mock_post.assert_called_once_with(mock.ANY, 'node_info', {}, [], {})

    def test_manager_is_cached(self):
        self.assertIs(plugins_base.processing_hooks_manager(),
                      plugins_base.processing_hooks_manager())


@mock.patch.object(utils, 'spawn_n')
@mock.patch.object(firewall, 'init')
@mock.patch.object(utils, 'add_auth_middleware')
@mock.patch.object(utils, 'get_client')
@mock.patch.object(db, 'init')
class TestInit(test_base.BaseTest):
    def test_ok(self, mock_node_cache, mock_get_client, mock_auth,
                mock_firewall, mock_spawn_n):
        CONF.set_override('auth_strategy', 'keystone')
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
        CONF.set_override('auth_strategy', 'noauth')
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


class TestCreateSSLContext(test_base.BaseTest):

    def test_use_ssl_false(self):
        CONF.set_override('use_ssl', False)
        con = main.create_ssl_context()
        self.assertIsNone(con)

    @mock.patch.object(sys, 'version_info')
    def test_old_python_returns_none(self, mock_version_info):
        mock_version_info.__lt__.return_value = True
        CONF.set_override('use_ssl', True)
        con = main.create_ssl_context()
        self.assertIsNone(con)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_use_ssl_true(self, mock_cdc):
        CONF.set_override('use_ssl', True)
        m_con = mock_cdc()
        con = main.create_ssl_context()
        self.assertEqual(m_con, con)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_only_key_path_provided(self, mock_cdc):
        CONF.set_override('use_ssl', True)
        CONF.set_override('ssl_key_path', '/some/fake/path')
        mock_context = mock_cdc()
        con = main.create_ssl_context()
        self.assertEqual(mock_context, con)
        self.assertFalse(mock_context.load_cert_chain.called)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_only_cert_path_provided(self, mock_cdc):
        CONF.set_override('use_ssl', True)
        CONF.set_override('ssl_cert_path', '/some/fake/path')
        mock_context = mock_cdc()
        con = main.create_ssl_context()
        self.assertEqual(mock_context, con)
        self.assertFalse(mock_context.load_cert_chain.called)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_both_paths_provided(self, mock_cdc):
        key_path = '/some/fake/path/key'
        cert_path = '/some/fake/path/cert'
        CONF.set_override('use_ssl', True)
        CONF.set_override('ssl_key_path', key_path)
        CONF.set_override('ssl_cert_path', cert_path)
        mock_context = mock_cdc()
        con = main.create_ssl_context()
        self.assertEqual(mock_context, con)
        mock_context.load_cert_chain.assert_called_once_with(cert_path,
                                                             key_path)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_load_cert_chain_fails(self, mock_cdc):
        CONF.set_override('use_ssl', True)
        key_path = '/some/fake/path/key'
        cert_path = '/some/fake/path/cert'
        CONF.set_override('use_ssl', True)
        CONF.set_override('ssl_key_path', key_path)
        CONF.set_override('ssl_cert_path', cert_path)
        mock_context = mock_cdc()
        mock_context.load_cert_chain.side_effect = IOError('Boom!')
        con = main.create_ssl_context()
        self.assertEqual(mock_context, con)
        mock_context.load_cert_chain.assert_called_once_with(cert_path,
                                                             key_path)
