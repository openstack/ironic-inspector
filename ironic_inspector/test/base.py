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

import tempfile
import unittest

import mock
from oslo_config import cfg

from ironic_inspector.common import i18n
# Import configuration options
from ironic_inspector import conf  # noqa
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base

CONF = cfg.CONF


def init_test_conf():
    try:
        # Functional tests
        CONF.reload_config_files()
        # Unit tests
    except Exception:
        CONF.reset()
    for group in ('firewall', 'processing', 'ironic'):
        CONF.register_group(cfg.OptGroup(group))
    if not CONF.database:
        # Might be set in functional tests
        db_file = tempfile.NamedTemporaryFile()
        CONF.set_override('database', db_file.name)
    else:
        db_file = None
    node_cache._DB_NAME = None
    return db_file


class BaseTest(unittest.TestCase):
    def setUp(self):
        super(BaseTest, self).setUp()
        self.db_file = init_test_conf()
        self.db = node_cache._db()
        if self.db_file:
            self.addCleanup(lambda: self.db_file.close())
        plugins_base._HOOKS_MGR = None
        for name in ('_', '_LI', '_LW', '_LE', '_LC'):
            patch = mock.patch.object(i18n, name, lambda s: s)
            patch.start()
            # 'p=patch' magic is due to how closures work
            self.addCleanup(lambda p=patch: p.stop())


class NodeTest(BaseTest):
    def setUp(self):
        super(NodeTest, self).setUp()
        self.uuid = '1a1a1a1a-2b2b-3c3c-4d4d-5e5e5e5e5e5e'
        self.bmc_address = '1.2.3.4'
        self.macs = ['11:22:33:44:55:66', '66:55:44:33:22:11']
        self.node = mock.Mock(driver='pxe_ipmitool',
                              driver_info={'ipmi_address': self.bmc_address},
                              properties={'cpu_arch': 'i386', 'local_gb': 40},
                              uuid=self.uuid,
                              power_state='power on',
                              provision_state='inspecting',
                              extra={},
                              instance_uuid=None,
                              maintenance=False)
