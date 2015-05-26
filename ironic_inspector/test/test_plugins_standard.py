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

import base64
import os
import shutil
import tempfile

from oslo_config import cfg

from ironic_inspector.plugins import standard as std_plugins
from ironic_inspector import process
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = cfg.CONF


class TestRamdiskError(test_base.BaseTest):
    def setUp(self):
        super(TestRamdiskError, self).setUp()
        self.msg = 'BOOM'
        self.bmc_address = '1.2.3.4'
        self.data = {
            'error': self.msg,
            'ipmi_address': self.bmc_address,
        }

        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.tempdir))
        CONF.set_override('ramdisk_logs_dir', self.tempdir, 'processing')

    def test_no_logs(self):
        self.assertRaisesRegexp(utils.Error,
                                self.msg,
                                process.process, self.data)
        self.assertEqual([], os.listdir(self.tempdir))

    def test_logs_disabled(self):
        self.data['logs'] = 'some log'
        CONF.set_override('ramdisk_logs_dir', None, 'processing')

        self.assertRaisesRegexp(utils.Error,
                                self.msg,
                                process.process, self.data)
        self.assertEqual([], os.listdir(self.tempdir))

    def test_logs(self):
        log = b'log contents'
        self.data['logs'] = base64.b64encode(log)

        self.assertRaisesRegexp(utils.Error,
                                self.msg,
                                process.process, self.data)

        files = os.listdir(self.tempdir)
        self.assertEqual(1, len(files))
        filename = files[0]
        self.assertTrue(filename.startswith('bmc_%s_' % self.bmc_address),
                        '%s does not start with bmc_%s'
                        % (filename, self.bmc_address))
        with open(os.path.join(self.tempdir, filename), 'rb') as fp:
            self.assertEqual(log, fp.read())

    def test_logs_create_dir(self):
        shutil.rmtree(self.tempdir)
        self.data['logs'] = base64.b64encode(b'log')

        self.assertRaisesRegexp(utils.Error,
                                self.msg,
                                process.process, self.data)

        files = os.listdir(self.tempdir)
        self.assertEqual(1, len(files))

    def test_logs_without_error(self):
        log = b'log contents'
        del self.data['error']
        self.data['logs'] = base64.b64encode(log)

        std_plugins.RamdiskErrorHook().before_processing(self.data)

        files = os.listdir(self.tempdir)
        self.assertFalse(files)

    def test_always_store_logs(self):
        CONF.set_override('always_store_ramdisk_logs', True, 'processing')

        log = b'log contents'
        del self.data['error']
        self.data['logs'] = base64.b64encode(log)

        std_plugins.RamdiskErrorHook().before_processing(self.data)

        files = os.listdir(self.tempdir)
        self.assertEqual(1, len(files))
        filename = files[0]
        self.assertTrue(filename.startswith('bmc_%s_' % self.bmc_address),
                        '%s does not start with bmc_%s'
                        % (filename, self.bmc_address))
        with open(os.path.join(self.tempdir, filename), 'rb') as fp:
            self.assertEqual(log, fp.read())
