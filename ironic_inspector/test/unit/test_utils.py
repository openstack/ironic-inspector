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

from keystonemiddleware import auth_token
from oslo_config import cfg

from ironic_inspector import node_cache
from ironic_inspector.test import base
from ironic_inspector import utils
from ironicclient.v1 import node

try:
    from unittest import mock
except ImportError:
    import mock

CONF = cfg.CONF


class TestCheckAuth(base.BaseTest):
    def setUp(self):
        super(TestCheckAuth, self).setUp()
        CONF.set_override('auth_strategy', 'keystone')

    @mock.patch.object(auth_token, 'AuthProtocol')
    def test_middleware(self, mock_auth):
        CONF.set_override('admin_user', 'admin', 'keystone_authtoken')
        CONF.set_override('admin_tenant_name', 'admin', 'keystone_authtoken')
        CONF.set_override('admin_password', 'password', 'keystone_authtoken')
        CONF.set_override('auth_uri', 'http://127.0.0.1:5000',
                          'keystone_authtoken')
        CONF.set_override('identity_uri', 'http://127.0.0.1:35357',
                          'keystone_authtoken')

        app = mock.Mock(wsgi_app=mock.sentinel.app)
        utils.add_auth_middleware(app)

        call_args = mock_auth.call_args_list[0]
        args = call_args[0]
        self.assertEqual(mock.sentinel.app, args[0])
        args1 = args[1]

        self.assertEqual('admin', args1['admin_user'])
        self.assertEqual('admin', args1['admin_tenant_name'])
        self.assertEqual('password', args1['admin_password'])
        self.assertTrue(args1['delay_auth_decision'])
        self.assertEqual('http://127.0.0.1:5000', args1['auth_uri'])
        self.assertEqual('http://127.0.0.1:35357', args1['identity_uri'])

    def test_ok(self):
        request = mock.Mock(headers={'X-Identity-Status': 'Confirmed',
                                     'X-Roles': 'admin,member'})
        utils.check_auth(request)

    def test_invalid(self):
        request = mock.Mock(headers={'X-Identity-Status': 'Invalid'})
        self.assertRaises(utils.Error, utils.check_auth, request)

    def test_not_admin(self):
        request = mock.Mock(headers={'X-Identity-Status': 'Confirmed',
                                     'X-Roles': 'member'})
        self.assertRaises(utils.Error, utils.check_auth, request)

    def test_disabled(self):
        CONF.set_override('auth_strategy', 'noauth')
        request = mock.Mock(headers={'X-Identity-Status': 'Invalid'})
        utils.check_auth(request)


class TestProcessingLogger(base.BaseTest):
    def test_prefix_no_info(self):
        self.assertEqual('[unidentified node]',
                         utils.processing_logger_prefix())

    def test_prefix_only_uuid(self):
        node_info = node.Node(mock.Mock(), dict(uuid='NNN'))
        self.assertEqual('[node: NNN]',
                         utils.processing_logger_prefix(node_info=node_info))

    def test_prefix_only_bmc(self):
        data = {'inventory': {'bmc_address': '1.2.3.4'}}
        self.assertEqual('[node: BMC 1.2.3.4]',
                         utils.processing_logger_prefix(data=data))

    def test_prefix_only_mac(self):
        data = {'boot_interface': '01-aa-bb-cc-dd-ee-ff'}
        self.assertEqual('[node: MAC aa:bb:cc:dd:ee:ff]',
                         utils.processing_logger_prefix(data=data))

    def test_prefix_everything(self):
        node_info = node.Node(mock.Mock(), dict(uuid='NNN'))
        data = {'boot_interface': '01-aa-bb-cc-dd-ee-ff',
                'inventory': {'bmc_address': '1.2.3.4'}}
        self.assertEqual('[node: NNN MAC aa:bb:cc:dd:ee:ff BMC 1.2.3.4]',
                         utils.processing_logger_prefix(node_info=node_info,
                                                        data=data))

    def test_prefix_uuid_not_str(self):
        node_info = node.Node(mock.Mock(), dict(uuid=None))
        self.assertEqual('[node: None]',
                         utils.processing_logger_prefix(node_info=node_info))

    def test_prefix_NodeInfo_instance(self):
        node_info = node_cache.NodeInfo('NNN')
        self.assertEqual('[node: NNN]',
                         utils.processing_logger_prefix(node_info=node_info))

    def test_prefix_NodeInfo_instance_with_state(self):
        node_info = node_cache.NodeInfo('NNN', state='foobar')
        self.assertEqual('[node: NNN state foobar]',
                         utils.processing_logger_prefix(node_info=node_info))

    def test_adapter_no_bmc(self):
        CONF.set_override('log_bmc_address', False, 'processing')
        node_info = node.Node(mock.Mock(), dict(uuid='NNN'))
        data = {'boot_interface': '01-aa-bb-cc-dd-ee-ff',
                'inventory': {'bmc_address': '1.2.3.4'}}
        logger = utils.getProcessingLogger(__name__)
        msg, _kwargs = logger.process('foo', {'node_info': node_info,
                                              'data': data})
        self.assertEqual(
            '[node: NNN MAC aa:bb:cc:dd:ee:ff] foo',
            msg)

    def test_adapter_with_bmc(self):
        node_info = node.Node(mock.Mock(), dict(uuid='NNN'))
        data = {'boot_interface': '01-aa-bb-cc-dd-ee-ff',
                'inventory': {'bmc_address': '1.2.3.4'}}
        logger = utils.getProcessingLogger(__name__)
        msg, _kwargs = logger.process('foo', {'node_info': node_info,
                                              'data': data})
        self.assertEqual(
            '[node: NNN MAC aa:bb:cc:dd:ee:ff BMC 1.2.3.4] foo',
            msg)

    def test_adapter_empty_data(self):
        logger = utils.getProcessingLogger(__name__)
        msg, _kwargs = logger.process('foo', {'node_info': None,
                                              'data': None})
        self.assertEqual('[unidentified node] foo', msg)

    def test_adapter_no_data(self):
        logger = utils.getProcessingLogger(__name__)
        msg, _kwargs = logger.process('foo', {})
        self.assertEqual('foo', msg)


class TestIsoTimestamp(base.BaseTest):
    def test_ok(self):
        iso_date = '1970-01-01T00:00:00+00:00'
        self.assertEqual(iso_date, utils.iso_timestamp(0.0))

    def test_none(self):
        self.assertIsNone(utils.iso_timestamp(None))
