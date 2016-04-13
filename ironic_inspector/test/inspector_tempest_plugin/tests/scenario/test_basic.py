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

from tempest import test  # noqa

from ironic_inspector.test.inspector_tempest_plugin.tests.scenario \
    import manager


class InspectorBasicTest(manager.InspectorScenarioTest):
    @test.idempotent_id('03bf7990-bee0-4dd7-bf74-b97ad7b52a4b')
    @test.services('baremetal', 'compute', 'image',
                   'network', 'object_storage')
    def test_berametal_introspection_ops(self):
        """This smoke test case follows this basic set of operations:

        """
        pass
