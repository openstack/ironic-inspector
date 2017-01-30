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

from tempest.config import CONF
from tempest.lib import decorators
from tempest import test  # noqa

from ironic_inspector.test.inspector_tempest_plugin.tests import manager
from ironic_tempest_plugin.tests.scenario import baremetal_manager


class InspectorBasicTest(manager.InspectorScenarioTest):

    def verify_node_introspection_data(self, node):
        self.assertEqual('yes', node['extra']['rule_success'])
        data = self.introspection_data(node['uuid'])
        self.assertEqual(data['cpu_arch'],
                         self.flavor['properties']['cpu_arch'])
        self.assertEqual(int(data['memory_mb']),
                         int(self.flavor['ram']))
        self.assertEqual(int(data['cpus']), int(self.flavor['vcpus']))

    def verify_node_flavor(self, node):
        expected_cpus = self.flavor['vcpus']
        expected_memory_mb = self.flavor['ram']
        expected_cpu_arch = self.flavor['properties']['cpu_arch']
        disk_size = self.flavor['disk']
        ephemeral_size = self.flavor['OS-FLV-EXT-DATA:ephemeral']
        expected_local_gb = disk_size + ephemeral_size

        self.assertEqual(expected_cpus,
                         int(node['properties']['cpus']))
        self.assertEqual(expected_memory_mb,
                         int(node['properties']['memory_mb']))
        self.assertEqual(expected_local_gb,
                         int(node['properties']['local_gb']))
        self.assertEqual(expected_cpu_arch,
                         node['properties']['cpu_arch'])

    def verify_introspection_aborted(self, uuid):
        status = self.introspection_status(uuid)

        self.assertEqual('Canceled by operator', status['error'])
        self.assertTrue(status['finished'])

        self.wait_provisioning_state(
            uuid, 'inspect failed',
            timeout=CONF.baremetal.active_timeout,
            interval=self.wait_provisioning_state_interval)

    @decorators.idempotent_id('03bf7990-bee0-4dd7-bf74-b97ad7b52a4b')
    @test.services('compute', 'image', 'network', 'object_storage')
    def test_baremetal_introspection(self):
        """This smoke test case follows this set of operations:

            * Fetches expected properties from baremetal flavor
            * Removes all properties from nodes
            * Sets nodes to manageable state
            * Imports introspection rule basic_ops_rule.json
            * Inspects nodes
            * Verifies all properties are inspected
            * Verifies introspection data
            * Sets node to available state
            * Creates a keypair
            * Boots an instance using the keypair
            * Deletes the instance

        """
        # prepare introspection rule
        rule_path = self.get_rule_path("basic_ops_rule.json")
        self.rule_import(rule_path)
        self.addCleanup(self.rule_purge)

        for node_id in self.node_ids:
            self.introspect_node(node_id)

        # settle down introspection
        self.wait_for_introspection_finished(self.node_ids)
        for node_id in self.node_ids:
            self.wait_provisioning_state(
                node_id, 'manageable',
                timeout=CONF.baremetal_introspection.ironic_sync_timeout,
                interval=self.wait_provisioning_state_interval)

        for node_id in self.node_ids:
            node = self.node_show(node_id)
            self.verify_node_introspection_data(node)
            self.verify_node_flavor(node)

        for node_id in self.node_ids:
            self.baremetal_client.set_node_provision_state(node_id, 'provide')

        for node_id in self.node_ids:
            self.wait_provisioning_state(
                node_id, baremetal_manager.BaremetalProvisionStates.AVAILABLE,
                timeout=CONF.baremetal.active_timeout,
                interval=self.wait_provisioning_state_interval)

        self.wait_for_nova_aware_of_bvms()
        self.add_keypair()
        ins, _node = self.boot_instance()
        self.terminate_instance(ins)

    @decorators.idempotent_id('70ca3070-184b-4b7d-8892-e977d2bc2870')
    def test_introspection_abort(self):
        """This smoke test case follows this very basic set of operations:

            * Start nodes introspection
            * Wait until nodes power on
            * Abort introspection
            * Verifies nodes status and power state

        """
        # start nodes introspection
        for node_id in self.node_ids:
            self.introspect_node(node_id, remove_props=False)

        # wait for nodes power on
        for node_id in self.node_ids:
            self.wait_power_state(
                node_id,
                baremetal_manager.BaremetalPowerStates.POWER_ON)

        # abort introspection
        for node_id in self.node_ids:
            self.introspection_abort(node_id)

        # wait for nodes power off
        for node_id in self.node_ids:
            self.wait_power_state(
                node_id,
                baremetal_manager.BaremetalPowerStates.POWER_OFF)

        # verify nodes status and provision state
        for node_id in self.node_ids:
            self.verify_introspection_aborted(node_id)


class InspectorSmokeTest(manager.InspectorScenarioTest):

    @decorators.idempotent_id('a702d1f1-88e4-42ce-88ef-cba2d9e3312e')
    @test.attr(type='smoke')
    @test.services('object_storage')
    def test_baremetal_introspection(self):
        """This smoke test case follows this very basic set of operations:

            * Fetches expected properties from baremetal flavor
            * Removes all properties from one node
            * Sets the node to manageable state
            * Inspects the node
            * Sets the node to available state

        """
        # NOTE(dtantsur): we can't silently skip this test because it runs in
        # grenade with several other tests, and we won't have any indication
        # that it was not run.
        assert self.node_ids, "No available nodes"
        node_id = next(iter(self.node_ids))
        self.introspect_node(node_id)

        # settle down introspection
        self.wait_for_introspection_finished([node_id])
        self.wait_provisioning_state(
            node_id, 'manageable',
            timeout=CONF.baremetal_introspection.ironic_sync_timeout,
            interval=self.wait_provisioning_state_interval)
