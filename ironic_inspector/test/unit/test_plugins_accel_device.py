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

from ironic_inspector import node_cache
from ironic_inspector.plugins import accel_device
from ironic_inspector.test import base as test_base


class TestAccelDevicesHook(test_base.NodeTest):
    hook = accel_device.AccelDevicesHook()

    @mock.patch.object(node_cache.NodeInfo, 'update_properties',
                       autospec=True)
    def test_before_update(self, mock_update_props):
        self.data['pci_devices'] = [
            {"vendor_id": "10de", "product_id": "1eb8", "class": "1234",
             "bus": "0000:01:1f.0", "revision": "1"},
        ]
        expected_accels = [{'vendor_id': '10de', 'device_id': '1eb8',
                            'type': 'GPU', 'pci_address': '0000:01:1f.0',
                            'device_info': 'NVIDIA Corporation Tesla T4'}]
        self.hook.before_update(self.data, self.node_info)
        mock_update_props.assert_called_once_with(self.node_info,
                                                  accelerators=expected_accels)

    @mock.patch.object(node_cache.NodeInfo, 'update_properties',
                       autospec=True)
    def test_before_update_no_pci_info_from_ipa(self, mock_update_props):
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_update_props.called)

    @mock.patch.object(node_cache.NodeInfo, 'update_properties',
                       autospec=True)
    def test_before_update_no_match(self, mock_update_props):
        self.data['pci_devices'] = [
            {"vendor_id": "1234", "product_id": "1234", "class": "1234",
             "bus": "0000:01:1f.0", "revision": "1"},
        ]
        self.hook.before_update(self.data, self.node_info)
        self.assertFalse(mock_update_props.called)
