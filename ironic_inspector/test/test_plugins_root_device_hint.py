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

from ironic_inspector.plugins import root_device_hint
from ironic_inspector.test import base as test_base


class TestRootDeviceHint(test_base.NodeTest):

    def setUp(self):
        super(TestRootDeviceHint, self).setUp()
        self.hook = root_device_hint.RootDeviceHintHook()

    def _before_update(self, introspection_data):
        node_patches = []
        ports_patches = {}
        self.hook.before_update(introspection_data, self.node_info,
                                node_patches, ports_patches)
        self.assertFalse(ports_patches)
        return node_patches

    def test_missing_local_gb(self):
        introspection_data = {}
        self.hook.before_processing(introspection_data)

        self.assertEqual(1, introspection_data['local_gb'])

    def test_local_gb_not_changed(self):
        introspection_data = {'local_gb': 42}
        self.hook.before_processing(introspection_data)

        self.assertEqual(42, introspection_data['local_gb'])

    def test_no_previous_block_devices(self):
        introspection_data = {'block_devices': {'serials': ['foo', 'bar']}}
        node_patches = self._before_update(introspection_data)

        self.assertEqual('add',
                         node_patches[0]['op'])
        self.assertEqual('/extra/block_devices',
                         node_patches[0]['path'])
        self.assertEqual(introspection_data['block_devices'],
                         node_patches[0]['value'])

    def test_root_device_found(self):
        self.node.extra['block_devices'] = {'serials': ['foo', 'bar']}
        introspection_data = {'block_devices': {'serials': ['foo', 'baz']}}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

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
        introspection_data = {'block_devices': {'serials': ['foo', 'baz']}}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

        self.assertFalse(node_patches)

    def test_multiple_new_devices(self):
        self.node.extra['block_devices'] = {'serials': ['foo', 'bar']}
        introspection_data = {
            'block_devices': {'serials': ['foo', 'baz', 'qux']}
        }
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

        self.assertFalse(node_patches)

    def test_no_new_devices(self):
        self.node.extra['block_devices'] = {'serials': ['foo', 'bar']}
        introspection_data = {'block_devices': {'serials': ['foo', 'bar']}}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

        self.assertFalse(node_patches)

    def test_no_block_devices_from_ramdisk(self):
        introspection_data = {}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

        self.assertFalse(node_patches)
