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

from openstack import exceptions
from oslo_config import cfg

from ironic_inspector import node_cache
from ironic_inspector.plugins import physnet_cidr_map
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


class TestPhysnetCidrMapHook(test_base.NodeTest):
    hook = physnet_cidr_map.PhysnetCidrMapHook()

    def setUp(self):
        super(TestPhysnetCidrMapHook, self).setUp()
        self.data = {
            'inventory': {
                'interfaces': [{
                    'name': 'em1',
                    'mac_address': '11:11:11:11:11:11',
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
                           address=a) for a in ('11:11:11:11:11:11',)]
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node, ports=ports)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_expected_data(self, mock_patch):
        cfg.CONF.set_override('cidr_map', '1.1.1.0/24:physnet_a',
                              group='port_physnet')
        patches = [{'path': '/physical_network',
                    'value': 'physnet_a',
                    'op': 'add'}]
        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patches, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_no_matching_mapping_config(self, mock_patch):
        cfg.CONF.set_override('cidr_map', '2.2.2.0/24:physnet_b',
                              group='port_physnet')
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_expected_data_ipv6_lowercase(self, mock_patch):
        self.data['inventory']['interfaces'][0].pop('ipv4_address')
        self.data['inventory']['interfaces'][0]['ipv6_address'] = '2001:db8::1'
        cfg.CONF.set_override('cidr_map', '2001:db8::/64:physnet_b',
                              group='port_physnet')
        patches = [{'path': '/physical_network',
                    'value': 'physnet_b',
                    'op': 'add'}]
        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patches, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_expected_data_ipv6_uppercase(self, mock_patch):
        self.data['inventory']['interfaces'][0].pop('ipv4_address')
        self.data['inventory']['interfaces'][0]['ipv6_address'] = '2001:db8::1'
        cfg.CONF.set_override('cidr_map', '2001:DB8::/64:physnet_b',
                              group='port_physnet')
        patches = [{'path': '/physical_network',
                    'value': 'physnet_b',
                    'op': 'add'}]
        self.hook.before_update(self.data, self.node_info)
        self.assertCalledWithPatch(patches, mock_patch)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_no_mapping_in_config(self, mock_patch):
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_patch.called)

    def test_no_inventory(self):
        cfg.CONF.set_override('cidr_map', '1.1.1.0/24:physnet_a',
                              group='port_physnet')
        del self.data['inventory']
        self.assertRaises(utils.Error, self.hook.before_update,
                          self.data, self.node_info)

    @mock.patch('ironic_inspector.plugins.base_physnet.LOG.debug',
                autospec=True)
    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_interface_not_in_ironic(self, mock_patch, mock_log):
        cfg.CONF.set_override('cidr_map', '1.1.1.0/24:physnet_a',
                              group='port_physnet')
        self.node_info._ports = {}
        self.hook.before_update(self.data, self.node_info)
        self.assertTrue(mock_log.called)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_no_overwrite(self, mock_patch):
        ports = [mock.Mock(spec=['address', 'uuid', 'physical_network'],
                           address=a, physical_network='foo')
                 for a in ('11:11:11:11:11:11',)]
        node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                        node=self.node, ports=ports)
        cfg.CONF.set_override('overwrite_existing', False, group='processing')
        cfg.CONF.set_override('cidr_map', '1.1.1.0/24:physnet_a',
                              group='port_physnet')
        self.hook.before_update(self.data, node_info)
        self.assertFalse(mock_patch.called)

    @mock.patch('ironic_inspector.plugins.base_physnet.LOG.warning',
                autospec=True)
    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_patch_port_exception(self, mock_patch, mock_log):
        cfg.CONF.set_override('cidr_map', '1.1.1.0/24:physnet_a',
                              group='port_physnet')
        mock_patch.side_effect = exceptions.BadRequestException('invalid data')
        self.hook.before_update(self.data, self.node_info)
        log_msg = "Failed to update port %(uuid)s: %(error)s"
        mock_log.assert_called_with(log_msg, mock.ANY, node_info=mock.ANY)

    @mock.patch.object(node_cache.NodeInfo, 'patch_port', autospec=True)
    def test_no_ip_address_on_interface(self, mock_patch):
        cfg.CONF.set_override('cidr_map', '1.1.1.0/24:physnet_a',
                              group='port_physnet')
        data = {
            'inventory': {
                'interfaces': [{
                    'name': 'em1',
                    'mac_address': '11:11:11:11:11:11',
                }],
                'cpu': 1,
                'disks': 1,
                'memory': 1
            },
            'all_interfaces': {
                'em1': {},
            }
        }
        self.hook.before_update(data, self.node_info)
        self.assertFalse(mock_patch.called)
