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

from ironic_discoverd.plugins import edeploy
from ironic_discoverd.test import base as test_base


class TestEdeploy(test_base.NodeTest):

    def setUp(self):
        super(TestEdeploy, self).setUp()
        self.hook = edeploy.eDeployHook()

    def test_data_recieved(self):
        node_info = {'data': [['memory', 'total', 'size', '4294967296'],
                              ['cpu', 'physical', 'number', '1'],
                              ['cpu', 'logical', 'number', '1']]}
        self.hook.before_processing(node_info)
        node_patches, _ = self.hook.before_update(self.node, None, node_info)

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
        node_info = {'cats': 'meow'}
        self.hook.before_processing(node_info)
        node_patches, _ = self.hook.before_update(self.node, None, node_info)
        self.assertEqual(0, len(node_patches))
