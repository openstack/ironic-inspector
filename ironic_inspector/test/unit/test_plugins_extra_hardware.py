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

from ironic_inspector.plugins import extra_hardware
from ironic_inspector.test import base as test_base


class TestExtraHardware(test_base.NodeTest):
    hook = extra_hardware.ExtraHardwareHook()

    def test_data_recieved(self):
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     ['cpu', 'physical', 'number', '1'],
                     ['cpu', 'logical', 'number', '1']]}
        self.hook.before_processing(introspection_data)
        self.hook.before_update(introspection_data, self.node_info)

        expected = {
            'memory': {
                'total': {
                    'size': 4294967296
                }
            },
            'cpu': {
                'physical': {
                    'number': 1
                },
                'logical': {
                    'number': 1
                },
            }
        }

        self.assertEqual(expected, introspection_data['extra'])

    def test_data_not_in_edeploy_format(self):
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     ['cpu', 'physical', 'number', '1'],
                     {'interface': 'eth1'}]}
        self.hook.before_processing(introspection_data)
        self.hook.before_update(introspection_data, self.node_info)

        self.assertNotIn('data', introspection_data)

    def test_no_data_recieved(self):
        introspection_data = {'cats': 'meow'}
        self.hook.before_processing(introspection_data)
        self.hook.before_update(introspection_data, self.node_info)

    def test__convert_edeploy_data(self):
        introspection_data = [['Sheldon', 'J.', 'Plankton', '123'],
                              ['Larry', 'the', 'Lobster', None],
                              ['Eugene', 'H.', 'Krabs', 'The cashier']]

        data = self.hook._convert_edeploy_data(introspection_data)
        expected_data = {'Sheldon': {'J.': {'Plankton': 123}},
                         'Larry': {'the': {'Lobster': None}},
                         'Eugene': {'H.': {'Krabs': 'The cashier'}}}
        self.assertEqual(expected_data, data)
