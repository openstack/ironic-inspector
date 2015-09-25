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

import mock
from oslo_config import cfg
from oslo_utils import units

from ironic_inspector import node_cache
from ironic_inspector.plugins import base
from ironic_inspector.plugins import standard as std_plugins
from ironic_inspector import process
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = cfg.CONF


class TestSchedulerHook(test_base.NodeTest):
    def setUp(self):
        super(TestSchedulerHook, self).setUp()
        self.hook = std_plugins.SchedulerHook()
        self.data = {
            'local_gb': 20,
            'memory_mb': 1024,
            'cpus': 2,
            'cpu_arch': 'x86_64'
        }
        self.node_patches = []
        self.ports_patches = {}
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node)

    def test_hook_loadable_by_name(self):
        CONF.set_override('processing_hooks', 'scheduler', 'processing')
        ext = base.processing_hooks_manager()['scheduler']
        self.assertIsInstance(ext.obj, std_plugins.SchedulerHook)

    def test_missing(self):
        for key in self.data:
            new_data = self.data.copy()
            del new_data[key]
            self.assertRaisesRegexp(utils.Error, key,
                                    self.hook.before_update, new_data,
                                    self.node_info)

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_ok(self, mock_patch):
        patch = [
            {'path': '/properties/cpus', 'value': '2', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '1024', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '20', 'op': 'add'}
        ]

        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patch, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_no_overwrite(self, mock_patch):
        CONF.set_override('overwrite_existing', False, 'processing')
        self.node.properties = {
            'memory_mb': '4096',
            'cpu_arch': 'i686'
        }
        patch = [
            {'path': '/properties/cpus', 'value': '2', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '20', 'op': 'add'}
        ]

        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patch, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_root_disk(self, mock_patch):
        self.data['root_disk'] = {'name': '/dev/sda', 'size': 42 * units.Gi}
        patch = [
            {'path': '/properties/cpus', 'value': '2', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '1024', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '41', 'op': 'add'}
        ]

        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patch, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_root_disk_no_spacing(self, mock_patch):
        CONF.set_override('disk_partitioning_spacing', False, 'processing')
        self.data['root_disk'] = {'name': '/dev/sda', 'size': 42 * units.Gi}
        patch = [
            {'path': '/properties/cpus', 'value': '2', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '1024', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '42', 'op': 'add'}
        ]

        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patch, mock_patch)


class TestValidateInterfacesHook(test_base.NodeTest):
    def setUp(self):
        super(TestValidateInterfacesHook, self).setUp()
        self.hook = std_plugins.ValidateInterfacesHook()
        self.data = {
            'interfaces': {
                'em1': {'mac': '11:11:11:11:11:11', 'ip': '1.1.1.1'},
                'em2': {'mac': '22:22:22:22:22:22', 'ip': '2.2.2.2'},
                'em3': {'mac': '33:33:33:33:33:33'}
            },
            'boot_interface': '01-22-22-22-22-22-22',
        }
        self.orig_interfaces = self.data['interfaces'].copy()
        self.pxe_interface = self.data['interfaces']['em2']
        self.active_interfaces = {
            'em1': {'mac': '11:11:11:11:11:11', 'ip': '1.1.1.1'},
            'em2': {'mac': '22:22:22:22:22:22', 'ip': '2.2.2.2'},
        }

        self.existing_ports = [mock.Mock(spec=['address', 'uuid'],
                                         address=a)
                               for a in ('11:11:11:11:11:11',
                                         '44:44:44:44:44:44')]
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node,
                                             ports=self.existing_ports)

    def test_hook_loadable_by_name(self):
        CONF.set_override('processing_hooks', 'validate_interfaces',
                          'processing')
        ext = base.processing_hooks_manager()['validate_interfaces']
        self.assertIsInstance(ext.obj, std_plugins.ValidateInterfacesHook)

    def test_wrong_add_ports(self):
        CONF.set_override('add_ports', 'foobar', 'processing')
        self.assertRaises(SystemExit, std_plugins.ValidateInterfacesHook)

    def test_wrong_keep_ports(self):
        CONF.set_override('keep_ports', 'foobar', 'processing')
        self.assertRaises(SystemExit, std_plugins.ValidateInterfacesHook)

    def test_no_interfaces(self):
        self.assertRaisesRegexp(utils.Error, 'No interfaces',
                                self.hook.before_processing, {})

    def test_only_pxe(self):
        self.hook.before_processing(self.data)

        self.assertEqual({'em2': self.pxe_interface}, self.data['interfaces'])
        self.assertEqual([self.pxe_interface['mac']], self.data['macs'])
        self.assertEqual(self.orig_interfaces, self.data['all_interfaces'])

    def test_only_pxe_mac_format(self):
        self.data['boot_interface'] = '22:22:22:22:22:22'
        self.hook.before_processing(self.data)

        self.assertEqual({'em2': self.pxe_interface}, self.data['interfaces'])
        self.assertEqual([self.pxe_interface['mac']], self.data['macs'])
        self.assertEqual(self.orig_interfaces, self.data['all_interfaces'])

    def test_only_pxe_not_found(self):
        self.data['boot_interface'] = 'aa:bb:cc:dd:ee:ff'
        self.assertRaisesRegexp(utils.Error, 'No valid interfaces',
                                self.hook.before_processing, self.data)

    def test_only_pxe_no_boot_interface(self):
        del self.data['boot_interface']
        self.hook.before_processing(self.data)

        self.assertEqual(self.active_interfaces, self.data['interfaces'])
        self.assertEqual(sorted(i['mac'] for i in
                                self.active_interfaces.values()),
                         sorted(self.data['macs']))
        self.assertEqual(self.orig_interfaces, self.data['all_interfaces'])

    def test_only_active(self):
        CONF.set_override('add_ports', 'active', 'processing')
        self.hook.before_processing(self.data)

        self.assertEqual(self.active_interfaces, self.data['interfaces'])
        self.assertEqual(sorted(i['mac'] for i in
                                self.active_interfaces.values()),
                         sorted(self.data['macs']))
        self.assertEqual(self.orig_interfaces, self.data['all_interfaces'])

    def test_all(self):
        CONF.set_override('add_ports', 'all', 'processing')
        self.hook.before_processing(self.data)

        self.assertEqual(self.orig_interfaces, self.data['interfaces'])
        self.assertEqual(sorted(i['mac'] for i in
                                self.orig_interfaces.values()),
                         sorted(self.data['macs']))
        self.assertEqual(self.orig_interfaces, self.data['all_interfaces'])

    @mock.patch.object(node_cache.NodeInfo, 'delete_port', autospec=True)
    def test_keep_all(self, mock_delete_port):
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_delete_port.called)

    @mock.patch.object(node_cache.NodeInfo, 'delete_port')
    def test_keep_present(self, mock_delete_port):
        CONF.set_override('keep_ports', 'present', 'processing')
        self.data['all_interfaces'] = self.orig_interfaces
        self.hook.before_update(self.data, self.node_info)

        mock_delete_port.assert_called_once_with(self.existing_ports[1])

    @mock.patch.object(node_cache.NodeInfo, 'delete_port')
    def test_keep_added(self, mock_delete_port):
        CONF.set_override('keep_ports', 'added', 'processing')
        self.data['macs'] = [self.pxe_interface['mac']]
        self.hook.before_update(self.data, self.node_info)

        mock_delete_port.assert_any_call(self.existing_ports[0])
        mock_delete_port.assert_any_call(self.existing_ports[1])


class TestRootDiskSelection(test_base.NodeTest):
    def setUp(self):
        super(TestRootDiskSelection, self).setUp()
        self.hook = std_plugins.RootDiskSelectionHook()
        self.data = {
            'inventory': {
                'disks': [
                    {'model': 'Model 1', 'size': 20 * units.Gi,
                     'name': '/dev/sdb'},
                    {'model': 'Model 2', 'size': 5 * units.Gi,
                     'name': '/dev/sda'},
                    {'model': 'Model 3', 'size': 10 * units.Gi,
                     'name': '/dev/sdc'},
                    {'model': 'Model 4', 'size': 4 * units.Gi,
                     'name': '/dev/sdd'},
                    {'model': 'Too Small', 'size': 1 * units.Gi,
                     'name': '/dev/sde'},
                ]
            }
        }
        self.matched = self.data['inventory']['disks'][2].copy()
        self.node_info = mock.Mock(spec=node_cache.NodeInfo,
                                   uuid=self.uuid,
                                   **{'node.return_value': self.node})

    def test_no_hints(self):
        self.hook.before_update(self.data, self.node_info, None, None)

        self.assertNotIn('local_gb', self.data)
        self.assertNotIn('root_disk', self.data)

    @mock.patch.object(std_plugins.LOG, 'error')
    def test_no_inventory(self, mock_log):
        self.node.properties['root_device'] = {'model': 'foo'}
        del self.data['inventory']

        self.hook.before_update(self.data, self.node_info, None, None)

        self.assertNotIn('local_gb', self.data)
        self.assertNotIn('root_disk', self.data)
        self.assertTrue(mock_log.called)

    def test_no_disks(self):
        self.node.properties['root_device'] = {'size': 10}
        self.data['inventory']['disks'] = []

        self.assertRaisesRegexp(utils.Error,
                                'No disks found',
                                self.hook.before_update,
                                self.data, self.node_info, None, None)

    def test_one_matches(self):
        self.node.properties['root_device'] = {'size': 10}

        self.hook.before_update(self.data, self.node_info, None, None)

        self.assertEqual(self.matched, self.data['root_disk'])

    def test_all_match(self):
        self.node.properties['root_device'] = {'size': 10,
                                               'model': 'Model 3'}

        self.hook.before_update(self.data, self.node_info, None, None)

        self.assertEqual(self.matched, self.data['root_disk'])

    def test_one_fails(self):
        self.node.properties['root_device'] = {'size': 10,
                                               'model': 'Model 42'}

        self.assertRaisesRegexp(utils.Error,
                                'No disks satisfied root device hints',
                                self.hook.before_update,
                                self.data, self.node_info, None, None)

        self.assertNotIn('local_gb', self.data)
        self.assertNotIn('root_disk', self.data)


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
