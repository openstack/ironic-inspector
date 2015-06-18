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

from __future__ import print_function

import eventlet
eventlet.monkey_patch()

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import ironic_inspector_client as client
import mock
import requests

from ironic_inspector import main
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
database = %(db_file)s
"""

ROOT = './functest/env'

RAMDISK = ("https://raw.githubusercontent.com/openstack/diskimage-builder/"
           "master/elements/ironic-discoverd-ramdisk/"
           "init.d/80-ironic-discoverd-ramdisk")

JQ = "https://stedolan.github.io/jq/download/linux64/jq"


class Test(base.NodeTest):
    def setUp(self):
        super(Test, self).setUp()
        self.node.properties.clear()

        self.cli = utils.get_client()
        self.cli.reset_mock()
        self.cli.node.get.return_value = self.node
        self.cli.node.update.return_value = self.node

        self.temp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.temp))
        self.env = os.path.join(self.temp, 'env')
        shutil.copytree(ROOT, self.env)
        net_ifaces = os.path.join(self.env, 'net')
        os.mkdir(net_ifaces)
        for fname in ('lo', 'em1', 'em2', 'em3'):
            open(os.path.join(net_ifaces, fname), 'wb').close()

        ramdisk_url = os.environ.get('RAMDISK_SOURCE', RAMDISK)
        if re.match(r'^https?://', ramdisk_url):
            ramdisk = requests.get(ramdisk_url).content
        else:
            with open(ramdisk_url, 'rb') as f:
                ramdisk = f.read()
        ramdisk = ramdisk.replace('/proc/cpuinfo', os.path.join(self.env,
                                                                'cpuinfo.txt'))
        ramdisk = ramdisk.replace('/sys/class/net', net_ifaces)
        self.ramdisk_sh = os.path.join(self.env, 'ramdisk')
        with open(self.ramdisk_sh, 'wb') as f:
            f.write(ramdisk)

        # jq is not on gate slaves
        jq_path = os.path.join(self.env, 'jq')
        with open(jq_path, 'wb') as f:
            jq = requests.get(JQ, stream=True).raw
            shutil.copyfileobj(jq, f)
        os.chmod(jq_path, stat.S_IRWXU)

        old_wd = os.getcwd()
        os.chdir(self.temp)
        self.addCleanup(lambda: os.chdir(old_wd))

        # These properties come from fake tools in functest/env
        self.patch = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '464', 'op': 'add'}
        ]
        self.node.power_state = 'power off'

    def call_ramdisk(self):
        env = os.environ.copy()
        env['PATH'] = self.env + ':' + env.get('PATH', '')

        subprocess.check_call(['/bin/bash', '-eux', self.ramdisk_sh], env=env)

    def test_bmc(self):
        client.introspect(self.uuid, auth_token='token')
        eventlet.greenthread.sleep(1)
        self.cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                              'reboot')

        status = client.get_status(self.uuid, auth_token='token')
        self.assertEqual({'finished': False, 'error': None}, status)

        self.call_ramdisk()
        eventlet.greenthread.sleep(1)

        self.cli.node.update.assert_any_call(self.uuid, self.patch)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = client.get_status(self.uuid, auth_token='token')
        self.assertEqual({'finished': True, 'error': None}, status)

    def test_setup_ipmi(self):
        patch_credentials = [
            {'op': 'add', 'path': '/driver_info/ipmi_username',
             'value': 'admin'},
            {'op': 'add', 'path': '/driver_info/ipmi_password',
             'value': 'pwd'},
        ]
        self.node.maintenance = True
        client.introspect(self.uuid, auth_token='token',
                          new_ipmi_username='admin', new_ipmi_password='pwd')
        eventlet.greenthread.sleep(1)
        self.assertFalse(self.cli.node.set_power_state.called)

        status = client.get_status(self.uuid, auth_token='token')
        self.assertEqual({'finished': False, 'error': None}, status)

        self.call_ramdisk()
        eventlet.greenthread.sleep(1)

        self.cli.node.update.assert_any_call(self.uuid, self.patch)
        self.cli.node.update.assert_any_call(self.uuid, patch_credentials)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = client.get_status(self.uuid, auth_token='token')
        self.assertEqual({'finished': True, 'error': None}, status)

        with open(os.path.join(self.temp, 'ipmi_calls.txt'), 'rb') as f:
            lines = f.readlines()
            self.assertIn('user set name 2 admin\n', lines)
            self.assertIn('user set password 2 pwd\n', lines)


@mock.patch.object(utils, 'check_auth')
@mock.patch.object(utils, 'get_client')
def run(client_mock, keystone_mock):
    d = tempfile.mkdtemp()
    try:
        conf_file = os.path.join(d, 'test.conf')
        db_file = os.path.join(d, 'test.db')
        with open(conf_file, 'wb') as fp:
            fp.write(CONF % {'db_file': db_file})

        eventlet.greenthread.spawn_n(main.main,
                                     args=['--config-file', conf_file])
        eventlet.greenthread.sleep(1)
        suite = unittest.TestLoader().loadTestsFromTestCase(Test)
        res = unittest.TextTestRunner().run(suite)
        sys.exit(0 if res.wasSuccessful() else 1)
    finally:
        shutil.rmtree(d)


if __name__ == '__main__':
    run()
