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
eventlet.monkey_patch(thread=False)

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

import mock
import requests

from ironic_discoverd import client
from ironic_discoverd import conf
from ironic_discoverd import main
from ironic_discoverd.test import base
from ironic_discoverd import utils


CONF = """
[discoverd]
os_auth_url = http://url
os_username = user
os_password = password
os_tenant_name = tenant
manage_firewall = false
"""

ROOT = './functest/env'

RAMDISK = ("https://raw.githubusercontent.com/openstack/diskimage-builder/"
           "master/elements/ironic-discoverd-ramdisk/"
           "init.d/80-ironic-discoverd-ramdisk")

JQ = "https://stedolan.github.io/jq/download/linux64/jq"


class Test(base.NodeTest):
    def setUp(self):
        super(Test, self).setUp()
        conf.CONF.set('discoverd', 'manage_firewall', 'false')
        self.node.properties.clear()

        self.cli = utils.get_client()
        self.cli.node.get.return_value = self.node
        self.cli.node.update.return_value = self.node

        self.temp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.temp))
        self.env = os.path.join(self.temp, 'env')
        shutil.copytree(ROOT, self.env)
        net_ifaces = os.path.join(self.env, 'net')
        os.mkdir(net_ifaces)
        for fname in ('lo', 'em1', 'em2'):
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

        # These properties come from fake tools in functest/env
        self.patch = [
            {'op': 'add', 'path': '/properties/cpus', 'value': '4'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '12288'},
            {'path': '/properties/local_gb', 'value': '464', 'op': 'add'}
        ]

    def call_ramdisk(self):
        env = os.environ.copy()
        env['PATH'] = self.env + ':' + env.get('PATH', '')

        subprocess.check_call(['/bin/bash', '-eux', self.ramdisk_sh], env=env)

    def test_bmc(self):
        self.node.power_state = 'power off'
        client.introspect(self.uuid, auth_token='token')
        eventlet.greenthread.sleep(1)

        status = client.get_status(self.uuid, auth_token='token')
        self.assertEqual({'finished': False, 'error': None}, status)

        self.call_ramdisk()
        eventlet.greenthread.sleep(1)

        self.cli.node.update.assert_any_call(self.uuid, self.patch)
        self.cli.port.create.assert_called_once_with(
            node_uuid=self.uuid, address='11:22:33:44:55:66')

        status = client.get_status(self.uuid, auth_token='token')
        self.assertEqual({'finished': True, 'error': None}, status)


@mock.patch.object(utils, 'check_auth')
@mock.patch.object(utils, 'get_client')
def run(client_mock, keystone_mock):
    d = tempfile.mkdtemp()
    try:
        conf_file = os.path.join(d, 'test.conf')
        with open(conf_file, 'wb') as fp:
            fp.write(CONF)
        sys.argv[1:] = ['--config-file', conf_file]
        base.init_test_conf()

        eventlet.greenthread.spawn_n(main.main)
        eventlet.greenthread.sleep(1)
        suite = unittest.TestLoader().loadTestsFromTestCase(Test)
        res = unittest.TextTestRunner().run(suite)
        sys.exit(0 if res.wasSuccessful() else 1)
    finally:
        shutil.rmtree(d)


if __name__ == '__main__':
    run()
