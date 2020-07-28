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

from ironic_inspector.plugins import extra_hardware
from ironic_inspector.test import base as test_base


CONF = cfg.CONF


@mock.patch.object(extra_hardware.LOG, 'warning', autospec=True)
class TestExtraHardware(test_base.NodeTest):
    hook = extra_hardware.ExtraHardwareHook()

    def test_data_recieved(self, mock_warn):
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
        self.assertFalse(mock_warn.called)

    def test_data_recieved_with_errors(self, mock_warn):
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     [],
                     ['cpu', 'physical', 'number', '1'],
                     ['cpu', 'physical', 'WUT'],
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
        # An empty list is not a warning, a bad record is.
        self.assertEqual(1, mock_warn.call_count)

    def test_data_not_in_edeploy_format(self, mock_warn):
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     ['cpu', 'physical', 'number', '1'],
                     {'interface': 'eth1'}]}
        self.hook.before_processing(introspection_data)
        self.hook.before_update(introspection_data, self.node_info)
        self.assertNotIn('extra', introspection_data)
        self.assertIn('data', introspection_data)
        self.assertTrue(mock_warn.called)

    def test_data_not_in_edeploy_format_strict_mode(self, mock_warn):
        CONF.set_override('strict', True, group='extra_hardware')
        introspection_data = {
            'data': [['memory', 'total', 'size', '4294967296'],
                     ['cpu', 'physical', 'WUT']]
        }
        self.hook.before_processing(introspection_data)
        self.hook.before_update(introspection_data, self.node_info)
        self.assertNotIn('extra', introspection_data)
        self.assertNotIn('data', introspection_data)
        self.assertTrue(mock_warn.called)

    def test_no_data_recieved(self, mock_warn):
        introspection_data = {'cats': 'meow'}
        self.hook.before_processing(introspection_data)
        self.hook.before_update(introspection_data, self.node_info)
        self.assertTrue(mock_warn.called)
