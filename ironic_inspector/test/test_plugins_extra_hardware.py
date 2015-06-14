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

import json
try:
    from unittest import mock
except ImportError:
    import mock

from ironic_inspector.plugins import extra_hardware
from ironic_inspector.test import base as test_base


@mock.patch.object(extra_hardware.swift, 'SwiftAPI', autospec=True)
class TestExtraHardware(test_base.NodeTest):
    def setUp(self):
        super(TestExtraHardware, self).setUp()
        self.hook = extra_hardware.ExtraHardwareHook()

    def _before_update(self, introspection_data):
        node_patches = []
        ports_patches = {}
        self.hook.before_update(introspection_data, self.node_info,
                                node_patches, ports_patches)
        self.assertFalse(ports_patches)
        return node_patches

    def test_data_recieved(self, swift_mock):
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     ['cpu', 'physical', 'number', '1'],
                     ['cpu', 'logical', 'number', '1']]}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

        swift_conn = swift_mock.return_value
        name = 'extra_hardware-%s' % self.uuid
        data = json.dumps(introspection_data['data'])
        swift_conn.create_object.assert_called_once_with(name, data)
        self.assertEqual('add',
                         node_patches[0]['op'])
        self.assertEqual('/extra/hardware_swift_object',
                         node_patches[0]['path'])
        self.assertEqual(name,
                         node_patches[0]['value'])

    def test_no_data_recieved(self, swift_mock):
        introspection_data = {'cats': 'meow'}
        swift_conn = swift_mock.return_value
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)
        self.assertFalse(node_patches)
        self.assertFalse(swift_conn.create_object.called)
