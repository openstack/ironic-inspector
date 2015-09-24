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

import eventlet
eventlet.monkey_patch()

import contextlib
import json
import os
import shutil
import tempfile
import unittest

import mock
from oslo_config import cfg
from oslo_utils import units
import requests

from ironic_inspector import dbsync
from ironic_inspector import main
from ironic_inspector import rules
from ironic_inspector.test import base
from ironic_inspector import utils


CONF = """
[ironic]
os_auth_url = http://url
os_username = user
os_password = password
os_tenant_name = tenant
[firewall]
manage_firewall = False
[processing]
enable_setting_ipmi_credentials = True
[DEFAULT]
debug = True
[database]
connection = sqlite:///%(db_file)s
"""


DEFAULT_SLEEP = 2


class Base(base.NodeTest):
    ROOT_URL = 'http://127.0.0.1:5050'

    def setUp(self):
        super(Base, self).setUp()
        rules.delete_all()

        self.cli = utils.get_client()
        self.cli.reset_mock()
        self.cli.node.get.return_value = self.node
        self.cli.node.update.return_value = self.node
        self.cli.node.list.return_value = [self.node]

        # https://github.com/openstack/ironic-inspector/blob/master/HTTP-API.rst  # noqa
        self.data = {
            'cpus': 4,
            'cpu_arch': 'x86_64',
            'memory_mb': 12288,
            'local_gb': 464,
            'interfaces': {
                'eth1': {'mac': self.macs[0], 'ip': '1.2.1.2'},
                'eth2': {'mac': '12:12:21:12:21:12'},
                'eth3': {'mac': self.macs[1], 'ip': '1.2.1.1'},
            },
            'boot_interface': '01-' + self.macs[0].replace(':', '-'),
            'ipmi_address': self.bmc_address,
            'inventory': {
                'disks': [
                    {'name': '/dev/sda', 'model': 'Big Data Disk',
                     'size': 1000 * units.Gi},
                    {'name': '/dev/sdb', 'model': 'Small OS Disk',
                     'size': 20 * units.Gi},
                ]
            },
            'root_disk': {'name': '/dev/sda', 'model': 'Big Data Disk',
                          'size': 1000 * units.Gi},
        }
        self.data_old_ramdisk = {
            'cpus': 4,
            'cpu_arch': 'x86_64',
            'memory_mb': 12288,
            'local_gb': 464,
            'interfaces': {
                'eth1': {'mac': self.macs[0], 'ip': '1.2.1.2'},
                'eth2': {'mac': '12:12:21:12:21:12'},
                'eth3': {'mac': self.macs[1], 'ip': '1.2.1.1'},
            },
            'boot_interface': '01-' + self.macs[0].replace(':', '-'),
            'ipmi_address': self.bmc_address,
        }

        self.patch = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '999', 'op': 'add'}
        ]
        self.patch_old_ramdisk = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '464', 'op': 'add'}
        ]
        self.patch_root_hints = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '19', 'op': 'add'}
        ]

        self.node.power_state = 'power off'

    def call(self, method, endpoint, data=None, expect_error=None,
             api_version=None):
        if data is not None:
            data = json.dumps(data)
        endpoint = self.ROOT_URL + endpoint
        headers = {'X-Auth-Token': 'token'}
        if api_version:
            headers[main._VERSION_HEADER] = '%d.%d' % api_version
        res = getattr(requests, method.lower())(endpoint, data=data,
                                                headers=headers)
        if expect_error:
            self.assertEqual(expect_error, res.status_code)
        else:
            res.raise_for_status()
        return res

    def call_introspect(self, uuid, new_ipmi_username=None,
                        new_ipmi_password=None):
        endpoint = '/v1/introspection/%s' % uuid
        if new_ipmi_password:
            endpoint += '?new_ipmi_password=%s' % new_ipmi_password
            if new_ipmi_username:
                endpoint += '&new_ipmi_username=%s' % new_ipmi_username
        return self.call('post', endpoint)

    def call_get_status(self, uuid):
        return self.call('get', '/v1/introspection/%s' % uuid).json()

    def call_continue(self, data):
        return self.call('post', '/v1/continue', data=data).json()

    def call_add_rule(self, data):
        return self.call('post', '/v1/rules', data=data).json()

    def call_list_rules(self):
        return self.call('get', '/v1/rules').json()['rules']

    def call_delete_rules(self):
        self.call('delete', '/v1/rules')

    def call_delete_rule(self, uuid):
        self.call('delete', '/v1/rules/' + uuid)

    def call_get_rule(self, uuid):
        return self.call('get', '/v1/rules/' + uuid).json()


class Test(Base):
    def test_bmc(self):
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': False, 'error': None}, status)

        res = self.call_continue(self.data)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.cli.node.update.assert_called_once_with(self.uuid, mock.ANY)
        self.assertCalledWithPatch(self.patch, self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': True, 'error': None}, status)

    def test_old_ramdisk(self):
        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': False, 'error': None}, status)

        res = self.call_continue(self.data_old_ramdisk)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.assertCalledWithPatch(self.patch_old_ramdisk,
                                   self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': True, 'error': None}, status)

    def test_setup_ipmi(self):
        patch_credentials = [
            {'op': 'add', 'path': '/driver_info/ipmi_username',
             'value': 'admin'},
            {'op': 'add', 'path': '/driver_info/ipmi_password',
             'value': 'pwd'},
        ]
        self.node.provision_state = 'enroll'
        self.call_introspect(self.uuid, new_ipmi_username='admin',
                             new_ipmi_password='pwd')
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.assertFalse(self.cli.node.set_power_state.called)

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': False, 'error': None}, status)

        res = self.call_continue(self.data)
        self.assertEqual('admin', res['ipmi_username'])
        self.assertEqual('pwd', res['ipmi_password'])
        self.assertTrue(res['ipmi_setup_credentials'])
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.assertCalledWithPatch(self.patch + patch_credentials,
                                   self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': True, 'error': None}, status)

    def test_rules_api(self):
        res = self.call_list_rules()
        self.assertEqual([], res)

        rule = {'conditions': [],
                'actions': [{'action': 'fail', 'message': 'boom'}],
                'description': 'Cool actions'}
        res = self.call_add_rule(rule)
        self.assertTrue(res['uuid'])
        rule['uuid'] = res['uuid']
        rule['links'] = res['links']
        self.assertEqual(rule, res)

        res = self.call('get', rule['links'][0]['href']).json()
        self.assertEqual(rule, res)

        res = self.call_list_rules()
        self.assertEqual(rule['links'], res[0].pop('links'))
        self.assertEqual([{'uuid': rule['uuid'],
                           'description': 'Cool actions'}],
                         res)

        res = self.call_get_rule(rule['uuid'])
        self.assertEqual(rule, res)

        self.call_delete_rule(rule['uuid'])
        res = self.call_list_rules()
        self.assertEqual([], res)

        links = rule.pop('links')
        del rule['uuid']
        for _ in range(3):
            self.call_add_rule(rule)

        res = self.call_list_rules()
        self.assertEqual(3, len(res))

        self.call_delete_rules()
        res = self.call_list_rules()
        self.assertEqual([], res)

        self.call('get', links[0]['href'], expect_error=404)
        self.call('delete', links[0]['href'], expect_error=404)

    def test_introspection_rules(self):
        self.node.extra['bar'] = 'foo'
        rules = [
            {
                'conditions': [
                    {'field': 'memory_mb', 'op': 'eq', 'value': 12288},
                    {'field': 'local_gb', 'op': 'gt', 'value': 998},
                    {'field': 'local_gb', 'op': 'lt', 'value': 1000},
                ],
                'actions': [
                    {'action': 'set-attribute', 'path': '/extra/foo',
                     'value': 'bar'}
                ]
            },
            {
                'conditions': [
                    {'field': 'memory_mb', 'op': 'ge', 'value': 100500},
                ],
                'actions': [
                    {'action': 'set-attribute', 'path': '/extra/bar',
                     'value': 'foo'},
                    {'action': 'fail', 'message': 'boom'}
                ]
            }
        ]
        for rule in rules:
            self.call_add_rule(rule)

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.call_continue(self.data)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        # clean up for second rule
        self.cli.node.update.assert_any_call(
            self.uuid,
            [{'op': 'remove', 'path': '/extra/bar'}])
        # applying first rule
        self.cli.node.update.assert_any_call(
            self.uuid,
            [{'op': 'add', 'path': '/extra/foo', 'value': 'bar'}])

    def test_root_device_hints(self):
        self.node.properties['root_device'] = {'size': 20}

        self.call_introspect(self.uuid)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': False, 'error': None}, status)

        res = self.call_continue(self.data)
        self.assertEqual({'uuid': self.uuid}, res)
        eventlet.greenthread.sleep(DEFAULT_SLEEP)

        self.assertCalledWithPatch(self.patch_root_hints, self.cli.node.update)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = self.call_get_status(self.uuid)
        self.assertEqual({'finished': True, 'error': None}, status)


@contextlib.contextmanager
def mocked_server():
    d = tempfile.mkdtemp()
    try:
        conf_file = os.path.join(d, 'test.conf')
        db_file = os.path.join(d, 'test.db')
        with open(conf_file, 'wb') as fp:
            content = CONF % {'db_file': db_file}
            fp.write(content.encode('utf-8'))

        with mock.patch.object(utils, 'check_auth'):
            with mock.patch.object(utils, 'get_client'):
                dbsync.main(args=['--config-file', conf_file, 'upgrade'])

                cfg.CONF.reset()
                cfg.CONF.unregister_opt(dbsync.command_opt)

                eventlet.greenthread.spawn_n(main.main,
                                             args=['--config-file', conf_file],
                                             in_functional_test=True)
                eventlet.greenthread.sleep(1)
                # Wait for service to start up to 30 seconds
                for i in range(10):
                    try:
                        requests.get('http://127.0.0.1:5050/v1')
                    except requests.ConnectionError:
                        if i == 9:
                            raise
                        print('Service did not start yet')
                        eventlet.greenthread.sleep(3)
                    else:
                        break
                # start testing
                yield
                # Make sure all processes finished executing
                eventlet.greenthread.sleep(1)
    finally:
        shutil.rmtree(d)


if __name__ == '__main__':
    with mocked_server():
        unittest.main()
