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
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node)

    def test_hook_loadable_by_name(self):
        CONF.set_override('processing_hooks', 'scheduler', 'processing')
        ext = base.processing_hooks_manager()['scheduler']
        self.assertIsInstance(ext.obj, std_plugins.SchedulerHook)

    def test_no_root_disk(self):
        del self.inventory['disks']
        self.assertRaisesRegexp(utils.Error, 'disks key is missing or empty',
                                self.hook.before_update, self.data,
                                self.node_info)

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_ok(self, mock_patch):
        patch = [
            {'path': '/properties/cpus', 'value': '4', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '12288', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '999', 'op': 'add'}
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
            {'path': '/properties/cpus', 'value': '4', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '999', 'op': 'add'}
        ]

        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patch, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_root_disk_no_spacing(self, mock_patch):
        CONF.set_override('disk_partitioning_spacing', False, 'processing')
        patch = [
            {'path': '/properties/cpus', 'value': '4', 'op': 'add'},
            {'path': '/properties/cpu_arch', 'value': 'x86_64', 'op': 'add'},
            {'path': '/properties/memory_mb', 'value': '12288', 'op': 'add'},
            {'path': '/properties/local_gb', 'value': '1000', 'op': 'add'}
        ]

        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patch, mock_patch)


class TestValidateInterfacesHook(test_base.NodeTest):
    def setUp(self):
        super(TestValidateInterfacesHook, self).setUp()
        self.hook = std_plugins.ValidateInterfacesHook()
        self.existing_ports = [mock.Mock(spec=['address', 'uuid'],
                                         address=a)
                               for a in (self.macs[1],
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
        self.assertRaisesRegexp(utils.Error,
                                'Hardware inventory is empty or missing',
                                self.hook.before_processing, {})
        self.assertRaisesRegexp(utils.Error,
                                'Hardware inventory is empty or missing',
                                self.hook.before_processing, {'inventory': {}})
        del self.inventory['interfaces']
        self.assertRaisesRegexp(utils.Error,
                                'interfaces key is missing or empty',
                                self.hook.before_processing, self.data)

    def test_only_pxe(self):
        self.hook.before_processing(self.data)

        self.assertEqual(self.pxe_interfaces, self.data['interfaces'])
        self.assertEqual([self.pxe_mac], self.data['macs'])
        self.assertEqual(self.all_interfaces, self.data['all_interfaces'])

    def test_only_pxe_mac_format(self):
        self.data['boot_interface'] = self.pxe_mac
        self.hook.before_processing(self.data)

        self.assertEqual(self.pxe_interfaces, self.data['interfaces'])
        self.assertEqual([self.pxe_mac], self.data['macs'])
        self.assertEqual(self.all_interfaces, self.data['all_interfaces'])

    def test_only_pxe_not_found(self):
        self.data['boot_interface'] = 'aa:bb:cc:dd:ee:ff'
        self.assertRaisesRegexp(utils.Error, 'No suitable interfaces',
                                self.hook.before_processing, self.data)

    def test_only_pxe_no_boot_interface(self):
        del self.data['boot_interface']
        self.hook.before_processing(self.data)

        self.assertEqual(self.active_interfaces, self.data['interfaces'])
        self.assertEqual(sorted(i['mac'] for i in
                                self.active_interfaces.values()),
                         sorted(self.data['macs']))
        self.assertEqual(self.all_interfaces, self.data['all_interfaces'])

    def test_only_active(self):
        CONF.set_override('add_ports', 'active', 'processing')
        self.hook.before_processing(self.data)

        self.assertEqual(self.active_interfaces, self.data['interfaces'])
        self.assertEqual(sorted(i['mac'] for i in
                                self.active_interfaces.values()),
                         sorted(self.data['macs']))
        self.assertEqual(self.all_interfaces, self.data['all_interfaces'])

    def test_all(self):
        CONF.set_override('add_ports', 'all', 'processing')
        self.hook.before_processing(self.data)

        self.assertEqual(self.all_interfaces, self.data['interfaces'])
        self.assertEqual(sorted(i['mac'] for i in
                                self.all_interfaces.values()),
                         sorted(self.data['macs']))
        self.assertEqual(self.all_interfaces, self.data['all_interfaces'])

    def test_malformed_interfaces(self):
        self.inventory['interfaces'] = [
            # no name
            {'mac_address': '11:11:11:11:11:11', 'ipv4_address': '1.1.1.1'},
            # empty
            {},
        ]
        self.assertRaisesRegexp(utils.Error, 'No interfaces supplied',
                                self.hook.before_processing, self.data)

    def test_skipped_interfaces(self):
        CONF.set_override('add_ports', 'all', 'processing')
        self.inventory['interfaces'] = [
            # local interface (by name)
            {'name': 'lo', 'mac_address': '11:11:11:11:11:11',
             'ipv4_address': '1.1.1.1'},
            # local interface (by IP address)
            {'name': 'em1', 'mac_address': '22:22:22:22:22:22',
             'ipv4_address': '127.0.0.1'},
            # no MAC provided
            {'name': 'em3', 'ipv4_address': '2.2.2.2'},
            # malformed MAC provided
            {'name': 'em4', 'mac_address': 'foobar',
             'ipv4_address': '2.2.2.2'},
        ]
        self.assertRaisesRegexp(utils.Error, 'No suitable interfaces found',
                                self.hook.before_processing, self.data)

    @mock.patch.object(node_cache.NodeInfo, 'delete_port', autospec=True)
    def test_keep_all(self, mock_delete_port):
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_delete_port.called)

    @mock.patch.object(node_cache.NodeInfo, 'delete_port')
    def test_keep_present(self, mock_delete_port):
        CONF.set_override('keep_ports', 'present', 'processing')
        self.data['all_interfaces'] = self.all_interfaces
        self.hook.before_update(self.data, self.node_info)

        mock_delete_port.assert_called_once_with(self.existing_ports[1])

    @mock.patch.object(node_cache.NodeInfo, 'delete_port')
    def test_keep_added(self, mock_delete_port):
        CONF.set_override('keep_ports', 'added', 'processing')
        self.data['macs'] = [self.pxe_mac]
        self.hook.before_update(self.data, self.node_info)

        mock_delete_port.assert_any_call(self.existing_ports[0])
        mock_delete_port.assert_any_call(self.existing_ports[1])


class TestRootDiskSelection(test_base.NodeTest):
    def setUp(self):
        super(TestRootDiskSelection, self).setUp()
        self.hook = std_plugins.RootDiskSelectionHook()
        self.inventory['disks'] = [
            {'model': 'Model 1', 'size': 20 * units.Gi, 'name': '/dev/sdb'},
            {'model': 'Model 2', 'size': 5 * units.Gi, 'name': '/dev/sda'},
            {'model': 'Model 3', 'size': 10 * units.Gi, 'name': '/dev/sdc'},
            {'model': 'Model 4', 'size': 4 * units.Gi, 'name': '/dev/sdd'},
            {'model': 'Too Small', 'size': 1 * units.Gi, 'name': '/dev/sde'},
        ]
        self.matched = self.inventory['disks'][2].copy()
        self.node_info = mock.Mock(spec=node_cache.NodeInfo,
                                   uuid=self.uuid,
                                   **{'node.return_value': self.node})

    def test_no_hints(self):
        del self.data['root_disk']

        self.hook.before_update(self.data, self.node_info)

        self.assertNotIn('local_gb', self.data)
        self.assertNotIn('root_disk', self.data)

    def test_no_inventory(self):
        self.node.properties['root_device'] = {'model': 'foo'}
        del self.data['inventory']
        del self.data['root_disk']

        self.assertRaisesRegexp(utils.Error,
                                'Hardware inventory is empty or missing',
                                self.hook.before_update,
                                self.data, self.node_info)

        self.assertNotIn('local_gb', self.data)
        self.assertNotIn('root_disk', self.data)

    def test_no_disks(self):
        self.node.properties['root_device'] = {'size': 10}
        self.inventory['disks'] = []

        self.assertRaisesRegexp(utils.Error,
                                'disks key is missing or empty',
                                self.hook.before_update,
                                self.data, self.node_info)

    def test_one_matches(self):
        self.node.properties['root_device'] = {'size': 10}

        self.hook.before_update(self.data, self.node_info)

        self.assertEqual(self.matched, self.data['root_disk'])

    def test_all_match(self):
        self.node.properties['root_device'] = {'size': 10,
                                               'model': 'Model 3'}

        self.hook.before_update(self.data, self.node_info)

        self.assertEqual(self.matched, self.data['root_disk'])

    def test_one_fails(self):
        self.node.properties['root_device'] = {'size': 10,
                                               'model': 'Model 42'}
        del self.data['root_disk']

        self.assertRaisesRegexp(utils.Error,
                                'No disks satisfied root device hints',
                                self.hook.before_update,
                                self.data, self.node_info)

        self.assertNotIn('local_gb', self.data)
        self.assertNotIn('root_disk', self.data)

    def test_size_string(self):
        self.node.properties['root_device'] = {'size': '10'}
        self.hook.before_update(self.data, self.node_info)
        self.assertEqual(self.matched, self.data['root_disk'])

    def test_size_invalid(self):
        for bad_size in ('foo', None, {}):
            self.node.properties['root_device'] = {'size': bad_size}
            self.assertRaisesRegexp(utils.Error,
                                    'Invalid root device size hint',
                                    self.hook.before_update,
                                    self.data, self.node_info)


class TestRamdiskError(test_base.InventoryTest):
    def setUp(self):
        super(TestRamdiskError, self).setUp()
        self.msg = 'BOOM'
        self.bmc_address = '1.2.3.4'
        self.data['error'] = self.msg

    def test_no_logs(self):
        self.assertRaisesRegexp(utils.Error,
                                self.msg,
                                process.process, self.data)
