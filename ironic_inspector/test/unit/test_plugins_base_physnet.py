# Copyright (c) 2017 StackHPC Ltd.
#
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

from unittest import mock

from oslo_config import cfg

from ironic_inspector import node_cache
from ironic_inspector.plugins import base_physnet
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


class FakePortPhysnetHook(base_physnet.BasePhysnetHook):

    def get_physnet(self, port, iface_name, introspection_data):
        return


class TestBasePortPhysnetHook(test_base.NodeTest):
    hook = FakePortPhysnetHook()

    def setUp(self):
        super(TestBasePortPhysnetHook, self).setUp()
        self.data = {
            'inventory': {
                'interfaces': [{
                    'name': 'em1', 'mac_address': '11:11:11:11:11:11',
                    'ipv4_address': '1.1.1.1',
                }],
                'cpu': 1,
                'disks': 1,
                'memory': 1
            },
            'all_interfaces': {
                'em1': {},
            }
        }

        ports = [mock.Mock(spec=['address', 'uuid', 'physical_network'],
                           address=a, physical_network='physnet1')
                 for a in ('11:11:11:11:11:11',)]
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node, ports=ports)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    @mock.patch.object(FakePortPhysnetHook, 'get_physnet', autospec=True)
    def test_expected_data(self, mock_get, mock_patch):
        patches = [
            {'path': '/physical_network',
             'value': 'physnet2', 'op': 'add'},
        ]
        mock_get.return_value = 'physnet2'
        self.hook.before_update(self.data, self.node_info)
        port = list(self.node_info.ports().values())[0]
        mock_get.assert_called_once_with(self.hook, port, 'em1', self.data)
        self.assertCalledWithPatch(patches, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    @mock.patch.object(FakePortPhysnetHook, 'get_physnet', autospec=True)
    def test_noop(self, mock_get, mock_patch):
        mock_get.return_value = 'physnet1'
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_no_mapping(self, mock_patch):
        self.hook.physnet = None
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_interface_not_in_all_interfaces(self, mock_patch):
        self.data['all_interfaces'] = {}
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_interface_not_in_ironic(self, mock_patch):
        self.node_info._ports = {}
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)

    def test_no_inventory(self):
        del self.data['inventory']
        self.assertRaises(utils.Error, self.hook.before_update,
                          self.data, self.node_info)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_no_overwrite(self, mock_patch):
        cfg.CONF.set_override('overwrite_existing', False, group='processing')
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)
