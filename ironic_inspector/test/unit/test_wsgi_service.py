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

from ironic_inspector import db
from ironic_inspector import firewall
from ironic_inspector import main
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector.test import base as test_base
from ironic_inspector import utils
from ironic_inspector import wsgi_service


CONF = cfg.CONF


@mock.patch.object(firewall, 'clean_up', lambda: None)
@mock.patch.object(db, 'init', lambda: None)
@mock.patch.object(wsgi_service.WSGIService, '_init_host', lambda x: None)
@mock.patch.object(utils, 'add_auth_middleware')
class TestWSGIService(test_base.BaseTest):
    def setUp(self):
        super(TestWSGIService, self).setUp()
        self.app = self.useFixture(fixtures.MockPatchObject(
            main, 'app', autospec=True)).mock
        self.service = wsgi_service.WSGIService()

    def test_init_middleware(self, mock_auth):
        CONF.set_override('auth_strategy', 'keystone')
        self.service._init_middleware()

        mock_auth.assert_called_once_with(self.app)

    @mock.patch.object(wsgi_service.WSGIService, '_init_middleware')
    def test_run_ok(self, mock_init_middlw, mock_auth):
        self.service.run()

        mock_init_middlw.assert_called_once_with()
        self.app.run.assert_called_once_with(host='0.0.0.0', port=5050)

    @mock.patch.object(wsgi_service.LOG, 'info')
    def test_init_with_swift_storage(self, mock_log, mock_auth):

        CONF.set_override('store_data', 'swift', 'processing')
        msg = mock.call('Introspection data will be stored in Swift in the '
                        'container %s', CONF.swift.container)
        self.service.run()
        self.assertIn(msg, mock_log.call_args_list)

    def test_init_without_authenticate(self, mock_auth):

        CONF.set_override('auth_strategy', 'noauth')
        self.service.run()
        self.assertFalse(mock_auth.called)

    @mock.patch.object(wsgi_service.LOG, 'warning')
    def test_init_with_no_data_storage(self, mock_log, mock_auth):
        msg = ('Introspection data will not be stored. Change '
               '"[processing] store_data" option if this is not the '
               'desired behavior')
        self.service.run()
        mock_log.assert_called_once_with(msg)


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


@mock.patch.object(firewall, 'init')
@mock.patch.object(db, 'init')
class TestInit(test_base.BaseTest):
    def setUp(self):
        super(TestInit, self).setUp()
        # Tests default to a synchronous executor which can't be used here
        utils._EXECUTOR = None
        # Monkey patch for periodic tasks
        eventlet.monkey_patch()
        self.wsgi = wsgi_service.WSGIService()

    @mock.patch.object(firewall, 'clean_up', lambda: None)
    def tearDown(self):
        self.wsgi.shutdown()
        super(TestInit, self).tearDown()

    def test_ok(self,  mock_db, mock_firewall):
        self.wsgi._init_host()

        mock_db.assert_called_once_with()
        mock_firewall.assert_called_once_with()

    def test_init_without_manage_firewall(self, mock_db, mock_firewall):

        CONF.set_override('manage_firewall', False, 'firewall')
        self.wsgi._init_host()
        self.assertFalse(mock_firewall.called)

    @mock.patch.object(wsgi_service.LOG, 'critical')
    def test_init_failed_processing_hook(self, mock_log,
                                         mock_db, mock_firewall):

        CONF.set_override('processing_hooks', 'foo!', 'processing')
        plugins_base._HOOKS_MGR = None

        self.assertRaises(SystemExit, self.wsgi._init_host)
        mock_log.assert_called_once_with(
            'The following hook(s) are missing or failed to load: foo!')
