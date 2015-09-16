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

import unittest

import mock
from oslo_config import cfg
from oslo_db import options as db_opts
from oslo_log import log

from ironic_inspector.common import i18n
# Import configuration options
from ironic_inspector import conf  # noqa
from ironic_inspector import db
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
    try:
        # Functional tests
        log.register_options(CONF)
    except Exception:
        # Unit tests
        pass
    db_opts.set_defaults(CONF)
    CONF.set_default('slave_connection', False, group='database')
    CONF.set_default('max_retries', 10, group='database')
    if not CONF.database.connection:
        # Might be set in functional tests
        db_opts.set_defaults(CONF,
                             connection='sqlite:///')


class BaseTest(unittest.TestCase):
    def setUp(self):
        super(BaseTest, self).setUp()
        init_test_conf()
        self.session = db.get_session()
        engine = db.get_engine()
        db.Base.metadata.create_all(engine)
        engine.connect()
        self.addCleanup(db.get_engine().dispose)
        plugins_base._HOOKS_MGR = None
        for name in ('_', '_LI', '_LW', '_LE', '_LC'):
            patch = mock.patch.object(i18n, name, lambda s: s)
            patch.start()
            # 'p=patch' magic is due to how closures work
            self.addCleanup(lambda p=patch: p.stop())

    def assertPatchEqual(self, expected, actual):
        expected = sorted(expected, key=lambda p: p['path'])
        actual = sorted(actual, key=lambda p: p['path'])
        self.assertEqual(expected, actual)

    def assertCalledWithPatch(self, expected, mock_call):
        def _get_patch_param(call):
            try:
                return call[0][1]
            except IndexError:
                return call[0][0]

        actual = sum(map(_get_patch_param, mock_call.call_args_list), [])
        self.assertPatchEqual(actual, expected)


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
        self.ports = []
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node, ports=self.ports)
