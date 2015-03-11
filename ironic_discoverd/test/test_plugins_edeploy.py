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

from hardware import cmdb
from hardware import state
import mock
from oslo_config import cfg

from ironic_discoverd.plugins import edeploy
from ironic_discoverd.test import base as test_base
from ironic_discoverd import utils

CONF = cfg.CONF


def fake_load(obj, cfg_dir):
    obj._cfg_dir = cfg_dir
    obj._data = [('hw1', '*'), ]


@mock.patch.object(state.State, 'load', fake_load)
@mock.patch.object(state.State, '_load_specs',
                   lambda o, n: [('network', '$iface', 'serial', '$mac'),
                                 ('network', '$iface', 'ipv4', '$ipv4')])
class TestEdeploy(test_base.NodeTest):

    def setUp(self):
        super(TestEdeploy, self).setUp()
        basedir = os.path.dirname(os.path.abspath(__file__))
        CONF.set_override('configdir',
                          os.path.join(basedir, 'edeploy_conf'),
                          'edeploy')

    def test_hook(self):
        hook = edeploy.eDeployHook()
        node_info = {'data': [
            ['network', 'eth0', 'serial', '99:99:99:99:99:99'],
            ['network', 'eth0', 'ipv4', '192.168.100.12'],
        ]}
        hook.before_processing(node_info)
        self.assertEqual('hw1', node_info['hardware']['profile'])
        self.assertEqual('eth0', node_info['hardware']['iface'])
        self.assertEqual('192.168.100.12', node_info['hardware']['ipv4'])
        self.assertEqual('99:99:99:99:99:99',
                         node_info['interfaces']['eth0']['mac'])
        self.assertEqual([('network', 'eth0', 'serial', '99:99:99:99:99:99'),
                          ('network', 'eth0', 'ipv4', '192.168.100.12')],
                         node_info['edeploy_facts'])
        node_patches, _ = hook.before_update(self.node, None, node_info)
        self.assertEqual('/extra/configdrive_metadata',
                         node_patches[0]['path'])
        self.assertEqual('hw1',
                         node_patches[0]['value']['hardware']['profile'])
        self.assertEqual('/properties/capabilities',
                         node_patches[1]['path'])
        self.assertEqual('profile:hw1',
                         node_patches[1]['value'])
        self.assertEqual('/extra/edeploy_facts',
                         node_patches[2]['path'])
        self.assertEqual(('network', 'eth0', 'serial', '99:99:99:99:99:99'),
                         node_patches[2]['value'][0])

    def test_hook_multiple_capabilities(self):
        hook = edeploy.eDeployHook()
        self.node.properties['capabilities'] = 'cat:meow,profile:robin'
        node_info = {'hardware': {'profile': 'batman'}, 'edeploy_facts': []}
        node_patches, _ = hook.before_update(self.node,  None, node_info)
        self.assertIn('cat:meow', node_patches[1]['value'])
        self.assertIn('profile:batman', node_patches[1]['value'])
        # Assert the old profile is gone
        self.assertNotIn('profile:robin', node_patches[1]['value'])

    def test_hook_no_data(self):
        hook = edeploy.eDeployHook()
        node_info = {}
        self.assertRaises(utils.Error, hook.before_processing, node_info)

    @mock.patch.object(edeploy, 'LOG')
    def test_hook_no_profile(self, mock_log):
        hook = edeploy.eDeployHook()
        node_info = {'data': []}
        hook.before_processing(node_info)
        self.assertTrue(mock_log.warning.called)

    @mock.patch.object(cmdb, 'load_cmdb')
    def test_raid_configuration_passed(self, mock_load_cmdb):
        hook = edeploy.eDeployHook()
        mock_load_cmdb.return_value = [
            {'logical_disks': (
                {'disk_type': 'hdd',
                 'interface_type': 'sas',
                 'is_root_volume': 'true',
                 'raid_level': '1+0',
                 'size_gb': 50,
                 'volume_name': 'root_volume'},
                {'disk_type': 'hdd',
                 'interface_type': 'sas',
                 'number_of_physical_disks': 3,
                 'raid_level': '5',
                 'size_gb': 100,
                 'volume_name': 'data_volume'})}]
        node_info = {'data': [
            ['network', 'eth0', 'serial', '99:99:99:99:99:99'],
            ['network', 'eth0', 'ipv4', '192.168.100.12'],
        ]}

        hook.before_processing(node_info)
        self.assertIn('target_raid_configuration', node_info)

        node_patches, _ = hook.before_update(self.node, None, node_info)
        self.assertEqual('/extra/target_raid_configuration',
                         node_patches[3]['path'])

    @mock.patch.object(cmdb, 'load_cmdb')
    def test_bios_configuration_passed(self, mock_load_cmdb):
        hook = edeploy.eDeployHook()
        mock_load_cmdb.return_value = [
            {'bios_settings': {'ProcVirtualization': 'Disabled'}}]
        node_info = {'data': [
            ['network', 'eth0', 'serial', '99:99:99:99:99:99'],
            ['network', 'eth0', 'ipv4', '192.168.100.12'],
        ]}

        hook.before_processing(node_info)
        self.assertIn('bios_settings', node_info)

        node_patches, _ = hook.before_update(self.node, None, node_info)
        self.assertEqual('/extra/bios_settings',
                         node_patches[3]['path'])
