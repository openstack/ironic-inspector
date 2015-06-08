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

from ironic_inspector.plugins import edeploy
from ironic_inspector.test import base as test_base


class TestEdeploy(test_base.NodeTest):

    def setUp(self):
        super(TestEdeploy, self).setUp()
        self.hook = edeploy.eDeployHook()

    def _before_update(self, introspection_data):
        node_patches = []
        ports_patches = {}
        self.hook.before_update(introspection_data, self.node_info,
                                node_patches, ports_patches)
        self.assertFalse(ports_patches)
        return node_patches

    def test_data_recieved(self):
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     ['cpu', 'physical', 'number', '1'],
                     ['cpu', 'logical', 'number', '1']]}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)

        expected_value = [['memory', 'total', 'size', '4294967296'],
                          ['cpu', 'physical', 'number', '1'],
                          ['cpu', 'logical', 'number', '1'],
                          ['system', 'product', 'ironic_uuid', self.node.uuid]]
        self.assertEqual('add',
                         node_patches[0]['op'])
        self.assertEqual('/extra/edeploy_facts',
                         node_patches[0]['path'])
        self.assertEqual(expected_value,
                         node_patches[0]['value'])

    def test_no_data_recieved(self):
        introspection_data = {'cats': 'meow'}
        self.hook.before_processing(introspection_data)
        node_patches = self._before_update(introspection_data)
        self.assertFalse(node_patches)
