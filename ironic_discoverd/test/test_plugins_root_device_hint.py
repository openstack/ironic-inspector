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

from ironic_discoverd.plugins import root_device_hint
from ironic_discoverd.test import base as test_base


class TestRootDeviceHint(test_base.NodeTest):

    def setUp(self):
        super(TestRootDeviceHint, self).setUp()
        self.hook = root_device_hint.RootDeviceHintHook()

    def test_no_previous_block_devices(self):
        node_info = {'block_devices': {'serials': ['foo', 'bar']}}
        node_patches, _ = self.hook.before_update(self.node, None, node_info)

        self.assertEqual('add',
                         node_patches[0]['op'])
        self.assertEqual('/extra/block_devices',
                         node_patches[0]['path'])
        self.assertEqual(node_info['block_devices'],
                         node_patches[0]['value'])

    def test_root_device_found(self):
        self.node.extra['block_devices'] = {'serials': ['foo', 'bar']}
        node_info = {'block_devices': {'serials': ['foo', 'baz']}}
        self.hook.before_processing(node_info)
        node_patches, _ = self.hook.before_update(self.node, None, node_info)

        self.assertEqual('remove',
                         node_patches[0]['op'])
        self.assertEqual('/extra/block_devices',
                         node_patches[0]['path'])
        self.assertEqual('add',
                         node_patches[1]['op'])
        self.assertEqual('/properties/root_device',
                         node_patches[1]['path'])
        self.assertEqual({'serial': 'baz'},
                         node_patches[1]['value'])

    def test_root_device_already_exposed(self):
        self.node.properties['root_device'] = {'serial': 'foo'}
        node_info = {'block_devices': {'serials': ['foo', 'baz']}}
        self.hook.before_processing(node_info)
        node_patches, _ = self.hook.before_update(self.node, None, node_info)

        self.assertEqual(0, len(node_patches))

    def test_multiple_new_devices(self):
        self.node.extra['block_devices'] = {'serials': ['foo', 'bar']}
        node_info = {'block_devices': {'serials': ['foo', 'baz', 'qux']}}
        self.hook.before_processing(node_info)
        node_patches, _ = self.hook.before_update(self.node, None, node_info)

        self.assertEqual(0, len(node_patches))

    def test_no_new_devices(self):
        self.node.extra['block_devices'] = {'serials': ['foo', 'bar']}
        node_info = {'block_devices': {'serials': ['foo', 'bar']}}
        self.hook.before_processing(node_info)
        node_patches, _ = self.hook.before_update(self.node, None, node_info)

        self.assertEqual(0, len(node_patches))
