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

import ssl
import sys
import unittest

import eventlet  # noqa
import fixtures
import mock
from oslo_config import cfg

from ironic_inspector.test import base as test_base
from ironic_inspector import wsgi_service

CONF = cfg.CONF


class BaseWSGITest(test_base.BaseTest):
    def setUp(self):
        # generic mocks setUp method
        super(BaseWSGITest, self).setUp()
        self.app = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.app, 'app', autospec=True)).mock
        self.mock_log = self.useFixture(fixtures.MockPatchObject(
            wsgi_service, 'LOG')).mock
        self.service = wsgi_service.WSGIService()


class TestWSGIServiceInitMiddleware(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceInitMiddleware, self).setUp()
        self.mock_add_auth_middleware = self.useFixture(
            fixtures.MockPatchObject(wsgi_service.utils,
                                     'add_auth_middleware')).mock
        self.mock_add_cors_middleware = self.useFixture(
            fixtures.MockPatchObject(wsgi_service.utils,
                                     'add_cors_middleware')).mock
        # 'positive' settings
        CONF.set_override('auth_strategy', 'keystone')
        CONF.set_override('store_data', 'swift', 'processing')

    def test_init_middleware(self):
        self.service._init_middleware()

        self.mock_add_auth_middleware.assert_called_once_with(self.app)
        self.mock_add_cors_middleware.assert_called_once_with(self.app)

    def test_init_middleware_noauth(self):
        CONF.set_override('auth_strategy', 'noauth')
        self.service._init_middleware()

        self.mock_add_auth_middleware.assert_not_called()
        self.mock_log.warning.assert_called_once_with(
            'Starting unauthenticated, please check configuration')
        self.mock_add_cors_middleware.assert_called_once_with(self.app)


class TestWSGIServiceRun(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceRun, self).setUp()
        self.mock__init_middleware = self.useFixture(fixtures.MockPatchObject(
            self.service, '_init_middleware')).mock
        self.mock__create_ssl_context = self.useFixture(
            fixtures.MockPatchObject(self.service, '_create_ssl_context')).mock
        self.mock_shutdown = self.useFixture(fixtures.MockPatchObject(
            self.service, 'shutdown')).mock

        # 'positive' settings
        CONF.set_override('listen_address', '42.42.42.42')
        CONF.set_override('listen_port', 42)

    def test_run(self):
        self.service.run()

        self.mock__create_ssl_context.assert_called_once_with()
        self.mock__init_middleware.assert_called_once_with()
        self.app.run.assert_called_once_with(
            host=CONF.listen_address, port=CONF.listen_port,
            ssl_context=self.mock__create_ssl_context.return_value)
        self.mock_shutdown.assert_called_once_with()

    def test_run_no_ssl_context(self):
        self.mock__create_ssl_context.return_value = None

        self.service.run()
        self.mock__create_ssl_context.assert_called_once_with()
        self.mock__init_middleware.assert_called_once_with()
        self.app.run.assert_called_once_with(
            host=CONF.listen_address, port=CONF.listen_port)
        self.mock_shutdown.assert_called_once_with()

    def test_run_app_error(self):
        class MyError(Exception):
            pass

        error = MyError('Oops!')
        self.app.run.side_effect = error
        self.service.run()

        self.mock__create_ssl_context.assert_called_once_with()
        self.mock__init_middleware.assert_called_once_with()
        self.app.run.assert_called_once_with(
            host=CONF.listen_address, port=CONF.listen_port,
            ssl_context=self.mock__create_ssl_context.return_value)
        self.mock_shutdown.assert_called_once_with(error=str(error))


class TestWSGIServiceShutdown(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceShutdown, self).setUp()
        self.service = wsgi_service.WSGIService()
        self.mock_rpc_service = mock.MagicMock()
        self.service.rpc_service = self.mock_rpc_service
        self.mock_exit = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.sys, 'exit')).mock

    def test_shutdown(self):
        class MyError(Exception):
            pass
        error = MyError('Oops!')

        self.service.shutdown(error=error)
        self.mock_rpc_service.stop.assert_called_once_with()
        self.mock_exit.assert_called_once_with(error)


class TestCreateSSLContext(test_base.BaseTest):
    def setUp(self):
        super(TestCreateSSLContext, self).setUp()
        self.app = mock.Mock()
        self.service = wsgi_service.WSGIService()

    def test_use_ssl_false(self):
        CONF.set_override('use_ssl', False)
        con = self.service._create_ssl_context()
        self.assertIsNone(con)

    @mock.patch.object(sys, 'version_info')
    def test_old_python_returns_none(self, mock_version_info):
        mock_version_info.__lt__.return_value = True
        CONF.set_override('use_ssl', True)
        con = self.service._create_ssl_context()
        self.assertIsNone(con)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_use_ssl_true(self, mock_cdc):
        CONF.set_override('use_ssl', True)
        m_con = mock_cdc()
        con = self.service._create_ssl_context()
        self.assertEqual(m_con, con)

    @unittest.skipIf(sys.version_info[:3] < (2, 7, 9),
                     'This feature is unsupported in this version of python '
                     'so the tests will be skipped')
    @mock.patch.object(ssl, 'create_default_context', autospec=True)
    def test_only_key_path_provided(self, mock_cdc):
        CONF.set_override('use_ssl', True)
        CONF.set_override('ssl_key_path', '/some/fake/path')
        mock_context = mock_cdc()
        con = self.service._create_ssl_context()
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
        con = self.service._create_ssl_context()
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
        con = self.service._create_ssl_context()
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
        con = self.service._create_ssl_context()
        self.assertEqual(mock_context, con)
        mock_context.load_cert_chain.assert_called_once_with(cert_path,
                                                             key_path)


class TestWSGIServiceOnSigHup(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceOnSigHup, self).setUp()
        self.mock_spawn = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.eventlet, 'spawn')).mock
        self.mock_mutate_conf = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.CONF, 'mutate_config_files')).mock

    def test_on_sighup(self):
        self.service._handle_sighup()
        self.mock_spawn.assert_called_once_with(self.service._handle_sighup_bg)

    def test_on_sighup_bg(self):
        self.service._handle_sighup_bg()
        self.mock_mutate_conf.assert_called_once_with()
