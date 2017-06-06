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
        self.mock__shutting_down = (self.useFixture(fixtures.MockPatchObject(
            wsgi_service.semaphore, 'Semaphore', autospec=True))
            .mock.return_value)
        self.mock__shutting_down.acquire.return_value = True
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

    def test_init_middleware_no_store(self):
        CONF.set_override('store_data', 'none', 'processing')
        self.service._init_middleware()

        self.mock_add_auth_middleware.assert_called_once_with(self.app)
        self.mock_log.warning.assert_called_once_with(
            'Introspection data will not be stored. Change "[processing] '
            'store_data" option if this is not the desired behavior')
        self.mock_add_cors_middleware.assert_called_once_with(self.app)


class TestWSGIServiceInitHost(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceInitHost, self).setUp()
        self.mock_db_init = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.db, 'init')).mock
        self.mock_validate_processing_hooks = self.useFixture(
            fixtures.MockPatchObject(wsgi_service.plugins_base,
                                     'validate_processing_hooks')).mock
        self.mock_filter = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.pxe_filter, 'driver')).mock.return_value
        self.mock_periodic = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.periodics, 'periodic')).mock
        self.mock_PeriodicWorker = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.periodics, 'PeriodicWorker')).mock
        self.mock_executor = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.utils, 'executor')).mock
        self.mock_ExistingExecutor = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.periodics, 'ExistingExecutor')).mock
        self.mock_exit = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.sys, 'exit')).mock

    def assert_periodics(self):
        outer_cleanup_decorator_call = mock.call(
            spacing=CONF.clean_up_period)
        self.mock_periodic.assert_has_calls([
            outer_cleanup_decorator_call,
            mock.call()(wsgi_service.periodic_clean_up)])

        inner_decorator = self.mock_periodic.return_value
        inner_cleanup_decorator_call = mock.call(
            wsgi_service.periodic_clean_up)
        inner_decorator.assert_has_calls([inner_cleanup_decorator_call])

        self.mock_ExistingExecutor.assert_called_once_with(
            self.mock_executor.return_value)

        periodic_worker = self.mock_PeriodicWorker.return_value

        periodic_sync = self.mock_filter.get_periodic_sync_task.return_value
        callables = [(periodic_sync, None, None),
                     (inner_decorator.return_value, None, None)]
        self.mock_PeriodicWorker.assert_called_once_with(
            callables=callables,
            executor_factory=self.mock_ExistingExecutor.return_value,
            on_failure=self.service._periodics_watchdog)
        self.assertIs(periodic_worker, self.service._periodics_worker)

        self.mock_executor.return_value.submit.assert_called_once_with(
            self.service._periodics_worker.start)

    def test_init_host(self):
        self.service._init_host()

        self.mock_db_init.asset_called_once_with()
        self.mock_validate_processing_hooks.assert_called_once_with()
        self.mock_filter.init_filter.assert_called_once_with()
        self.assert_periodics()

    def test_init_host_validate_processing_hooks_exception(self):
        class MyError(Exception):
            pass

        error = MyError('Oops!')
        self.mock_validate_processing_hooks.side_effect = error

        # NOTE(milan): have to stop executing the test case at this point to
        # simulate a real sys.exit() call
        self.mock_exit.side_effect = SystemExit('Stop!')
        self.assertRaisesRegex(SystemExit, 'Stop!', self.service._init_host)

        self.mock_db_init.assert_called_once_with()
        self.mock_log.critical.assert_called_once_with(str(error))
        self.mock_exit.assert_called_once_with(1)
        self.mock_filter.init_filter.assert_not_called()


class TestWSGIServicePeriodicWatchDog(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServicePeriodicWatchDog, self).setUp()
        self.mock_get_callable_name = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.reflection, 'get_callable_name')).mock
        self.mock_spawn = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.eventlet, 'spawn')).mock

    def test__periodics_watchdog(self):
        error = RuntimeError('Oops!')

        self.service._periodics_watchdog(
            callable_=None, activity=None, spacing=None,
            exc_info=(None, error, None), traceback=None)

        self.mock_get_callable_name.assert_called_once_with(None)
        self.mock_spawn.assert_called_once_with(self.service.shutdown,
                                                error=str(error))


class TestWSGIServiceRun(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceRun, self).setUp()
        self.mock__init_host = self.useFixture(fixtures.MockPatchObject(
            self.service, '_init_host')).mock
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
        self.mock__init_host.assert_called_once_with()
        self.app.run.assert_called_once_with(
            host=CONF.listen_address, port=CONF.listen_port,
            ssl_context=self.mock__create_ssl_context.return_value)
        self.mock_shutdown.assert_called_once_with()

    def test_run_no_ssl_context(self):
        self.mock__create_ssl_context.return_value = None

        self.service.run()
        self.mock__create_ssl_context.assert_called_once_with()
        self.mock__init_middleware.assert_called_once_with()
        self.mock__init_host.assert_called_once_with()
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
        self.mock__init_host.assert_called_once_with()
        self.app.run.assert_called_once_with(
            host=CONF.listen_address, port=CONF.listen_port,
            ssl_context=self.mock__create_ssl_context.return_value)
        self.mock_shutdown.assert_called_once_with(error=str(error))


class TestWSGIServiceShutdown(BaseWSGITest):
    def setUp(self):
        super(TestWSGIServiceShutdown, self).setUp()
        self.mock_filter = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.pxe_filter, 'driver')).mock.return_value
        self.mock_executor = mock.Mock()
        self.mock_executor.alive = True
        self.mock_get_executor = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.utils, 'executor')).mock
        self.mock_get_executor.return_value = self.mock_executor
        self.service = wsgi_service.WSGIService()
        self.mock__periodic_worker = self.useFixture(fixtures.MockPatchObject(
            self.service, '_periodics_worker')).mock
        self.mock_exit = self.useFixture(fixtures.MockPatchObject(
            wsgi_service.sys, 'exit')).mock

    def test_shutdown(self):
        class MyError(Exception):
            pass

        error = MyError('Oops!')

        self.service.shutdown(error=error)

        self.mock__shutting_down.acquire.assert_called_once_with(
            blocking=False)
        self.mock__periodic_worker.stop.assert_called_once_with()
        self.mock__periodic_worker.wait.assert_called_once_with()
        self.assertIsNone(self.service._periodics_worker)
        self.mock_executor.shutdown.assert_called_once_with(wait=True)
        self.mock_filter.tear_down_filter.assert_called_once_with()
        self.mock__shutting_down.release.assert_called_once_with()
        self.mock_exit.assert_called_once_with(error)

    def test_shutdown_race(self):
        self.mock__shutting_down.acquire.return_value = False

        self.service.shutdown()

        self.mock__shutting_down.acquire.assert_called_once_with(
            blocking=False)
        self.mock_log.warning.assert_called_once_with(
            'Attempted to shut down while already shutting down')
        self.mock__periodic_worker.stop.assert_not_called()
        self.mock__periodic_worker.wait.assert_not_called()
        self.assertIs(self.mock__periodic_worker,
                      self.service._periodics_worker)
        self.mock_executor.shutdown.assert_not_called()
        self.mock_filter.tear_down_filter.assert_not_called()
        self.mock__shutting_down.release.assert_not_called()
        self.mock_exit.assert_not_called()

    def test_shutdown_worker_exception(self):
        class MyError(Exception):
            pass

        error = MyError('Oops!')
        self.mock__periodic_worker.wait.side_effect = error

        self.service.shutdown()

        self.mock__shutting_down.acquire.assert_called_once_with(
            blocking=False)
        self.mock__periodic_worker.stop.assert_called_once_with()
        self.mock__periodic_worker.wait.assert_called_once_with()
        self.mock_log.exception.assert_called_once_with(
            'Service error occurred when stopping periodic workers. Error: %s',
            error)
        self.assertIsNone(self.service._periodics_worker)
        self.mock_executor.shutdown.assert_called_once_with(wait=True)
        self.mock_filter.tear_down_filter.assert_called_once_with()
        self.mock__shutting_down.release.assert_called_once_with()
        self.mock_exit.assert_called_once_with(None)

    def test_shutdown_no_worker(self):
        self.service._periodics_worker = None

        self.service.shutdown()

        self.mock__shutting_down.acquire.assert_called_once_with(
            blocking=False)
        self.mock__periodic_worker.stop.assert_not_called()
        self.mock__periodic_worker.wait.assert_not_called()
        self.assertIsNone(self.service._periodics_worker)
        self.mock_executor.shutdown.assert_called_once_with(wait=True)
        self.mock_filter.tear_down_filter.assert_called_once_with()
        self.mock__shutting_down.release.assert_called_once_with()
        self.mock_exit.assert_called_once_with(None)

    def test_shutdown_stopped_executor(self):
        self.mock_executor.alive = False

        self.service.shutdown()

        self.mock__shutting_down.acquire.assert_called_once_with(
            blocking=False)
        self.mock__periodic_worker.stop.assert_called_once_with()
        self.mock__periodic_worker.wait.assert_called_once_with()
        self.assertIsNone(self.service._periodics_worker)
        self.mock_executor.shutdown.assert_not_called()
        self.mock_filter.tear_down_filter.assert_called_once_with()
        self.mock__shutting_down.release.assert_called_once_with()
        self.mock_exit.assert_called_once_with(None)


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
