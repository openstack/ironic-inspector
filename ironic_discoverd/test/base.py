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

import os
import unittest

import mock

from ironic_discoverd import conf
from ironic_discoverd import node_cache
from ironic_discoverd.plugins import base as plugins_base


class BaseTest(unittest.TestCase):
    def setUp(self):
        super(BaseTest, self).setUp()
        conf.init_conf()
        conf.CONF.add_section('discoverd')
        conf.CONF.set('discoverd', 'database', '')
        node_cache._DB_NAME = None
        self.db = node_cache._db()
        self.addCleanup(lambda: os.unlink(node_cache._DB_NAME))
        plugins_base._HOOKS_MGR = None


class NodeTest(BaseTest):
    def setUp(self):
        super(NodeTest, self).setUp()
        self.uuid = 'uuid'
        self.bmc_address = '1.2.3.4'
        self.macs = ['11:22:33:44:55:66', '66:55:44:33:22:11']
        self.node = mock.Mock(driver_info={'ipmi_address': self.bmc_address},
                              properties={'cpu_arch': 'i386', 'local_gb': 40},
                              uuid=self.uuid,
                              power_state='power on',
                              extra={'on_discovery': 'true'},
                              instance_uuid=None)
