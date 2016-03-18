# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Mostly copied from ironic/tests/test_swift.py

try:
    from unittest import mock
except ImportError:
    import mock
from swiftclient import client as swift_client
from swiftclient import exceptions as swift_exception

from ironic_inspector.common import keystone
from ironic_inspector.common import swift
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


class BaseTest(test_base.NodeTest):
    def setUp(self):
        super(BaseTest, self).setUp()
        self.all_macs = self.macs + ['DE:AD:BE:EF:DE:AD']
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
                'em3': {'mac': self.all_macs[2]},
            },
            'boot_interface': '01-' + self.pxe_mac.replace(':', '-'),
        }


@mock.patch.object(keystone, 'register_auth_opts')
@mock.patch.object(keystone, 'get_session')
@mock.patch.object(swift_client, 'Connection', autospec=True)
class SwiftTestCase(BaseTest):

    def setUp(self):
        super(SwiftTestCase, self).setUp()
        swift.reset_swift_session()
        self.swift_exception = swift_exception.ClientException('', '')
        self.cfg.config(group='swift',
                        os_service_type='object-store',
                        os_endpoint_type='internalURL',
                        os_region='somewhere',
                        max_retries=2)
        self.addCleanup(swift.reset_swift_session)

    def test___init__(self, connection_mock, load_mock, opts_mock):
        swift_url = 'http://swiftapi'
        token = 'secret_token'
        mock_sess = mock.Mock()
        mock_sess.get_token.return_value = token
        mock_sess.get_endpoint.return_value = swift_url
        mock_sess.verify = False
        load_mock.return_value = mock_sess
        swift.SwiftAPI()
        params = {'retries': 2,
                  'preauthurl': swift_url,
                  'preauthtoken': token,
                  'insecure': True}
        connection_mock.assert_called_once_with(**params)
        mock_sess.get_endpoint.assert_called_once_with(
            service_type='object-store',
            endpoint_type='internalURL',
            region_name='somewhere')

    def test_create_object(self, connection_mock, load_mock, opts_mock):
        swiftapi = swift.SwiftAPI()
        connection_obj_mock = connection_mock.return_value

        connection_obj_mock.put_object.return_value = 'object-uuid'

        object_uuid = swiftapi.create_object('object', 'some-string-data')

        connection_obj_mock.put_container.assert_called_once_with('ironic-'
                                                                  'inspector')
        connection_obj_mock.put_object.assert_called_once_with(
            'ironic-inspector', 'object', 'some-string-data', headers=None)
        self.assertEqual('object-uuid', object_uuid)

    def test_create_object_create_container_fails(self, connection_mock,
                                                  load_mock, opts_mock):
        swiftapi = swift.SwiftAPI()
        connection_obj_mock = connection_mock.return_value
        connection_obj_mock.put_container.side_effect = self.swift_exception
        self.assertRaises(utils.Error, swiftapi.create_object, 'object',
                          'some-string-data')
        connection_obj_mock.put_container.assert_called_once_with('ironic-'
                                                                  'inspector')
        self.assertFalse(connection_obj_mock.put_object.called)

    def test_create_object_put_object_fails(self, connection_mock, load_mock,
                                            opts_mock):
        swiftapi = swift.SwiftAPI()
        connection_obj_mock = connection_mock.return_value
        connection_obj_mock.put_object.side_effect = self.swift_exception
        self.assertRaises(utils.Error, swiftapi.create_object, 'object',
                          'some-string-data')
        connection_obj_mock.put_container.assert_called_once_with('ironic-'
                                                                  'inspector')
        connection_obj_mock.put_object.assert_called_once_with(
            'ironic-inspector', 'object', 'some-string-data', headers=None)

    def test_get_object(self, connection_mock, load_mock, opts_mock):
        swiftapi = swift.SwiftAPI()
        connection_obj_mock = connection_mock.return_value

        expected_obj = self.data
        connection_obj_mock.get_object.return_value = ('headers', expected_obj)

        swift_obj = swiftapi.get_object('object')

        connection_obj_mock.get_object.assert_called_once_with(
            'ironic-inspector', 'object')
        self.assertEqual(expected_obj, swift_obj)

    def test_get_object_fails(self, connection_mock, load_mock, opts_mock):
        swiftapi = swift.SwiftAPI()
        connection_obj_mock = connection_mock.return_value
        connection_obj_mock.get_object.side_effect = self.swift_exception
        self.assertRaises(utils.Error, swiftapi.get_object,
                          'object')
        connection_obj_mock.get_object.assert_called_once_with(
            'ironic-inspector', 'object')
