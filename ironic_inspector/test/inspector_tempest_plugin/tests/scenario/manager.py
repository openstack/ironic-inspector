#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.scenario import manager


class InspectorScenarioTest(manager.BaremetalScenarioTest):
    """Provide harness to do Inspector scenario tests."""

    credentials = ['primary', 'admin']

    @classmethod
    def setup_clients(cls):
        super(InspectorScenarioTest, cls).setup_clients()

    def setUp(self):
        super(InspectorScenarioTest, self).setUp()
