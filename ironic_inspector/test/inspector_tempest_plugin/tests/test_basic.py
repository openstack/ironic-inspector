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

import tempest

from tempest.config import CONF
from tempest import test  # noqa

from ironic_inspector.test.inspector_tempest_plugin.tests import manager
from ironic_tempest_plugin.tests.api.admin.api_microversion_fixture import \
    APIMicroversionFixture as IronicMicroversionFixture
from ironic_tempest_plugin.tests.scenario.baremetal_manager import \
    BaremetalProvisionStates
from tempest.lib.common.api_version_utils import LATEST_MICROVERSION


class InspectorBasicTest(manager.InspectorScenarioTest):
    wait_provisioning_state_interval = 15

    def node_cleanup(self, node_id):
        if (self.node_show(node_id)['provision_state'] ==
           BaremetalProvisionStates.AVAILABLE):
            return
        try:
            self.baremetal_client.set_node_provision_state(node_id, 'provide')
        except tempest.lib.exceptions.RestClientException:
            # maybe node already cleaning or available
            pass

        self.wait_provisioning_state(
            node_id, [BaremetalProvisionStates.AVAILABLE,
                      BaremetalProvisionStates.NOSTATE],
            timeout=CONF.baremetal.unprovision_timeout,
            interval=self.wait_provisioning_state_interval)

    def introspect_node(self, node_id):
        # in case there are properties remove those
        patch = {('properties/%s' % key): None for key in
                 self.node_show(node_id)['properties']}
        # reset any previous rule result
        patch['extra/rule_success'] = None
        self.node_update(node_id, patch)

        self.baremetal_client.set_node_provision_state(node_id, 'manage')
        self.baremetal_client.set_node_provision_state(node_id, 'inspect')
        self.addCleanup(self.node_cleanup, node_id)

    def setUp(self):
        super(InspectorBasicTest, self).setUp()
        # we rely on the 'available' provision_state; using latest
        # microversion
        self.useFixture(IronicMicroversionFixture(LATEST_MICROVERSION))
        # avoid testing nodes that aren't available
        self.node_ids = {node['uuid'] for node in
                         self.node_filter(filter=lambda node:
                                          node['provision_state'] ==
                                          BaremetalProvisionStates.AVAILABLE)}
        if not self.node_ids:
            self.skipTest('no available nodes detected')
        self.rule_purge()

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

    @test.idempotent_id('03bf7990-bee0-4dd7-bf74-b97ad7b52a4b')
    @test.services('baremetal', 'compute', 'image',
                   'network', 'object_storage')
    def test_baremetal_introspection(self):
        """This smoke test case follows this basic set of operations:

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
                node_id, BaremetalProvisionStates.AVAILABLE,
                timeout=CONF.baremetal.active_timeout,
                interval=self.wait_provisioning_state_interval)

        self.wait_for_nova_aware_of_bvms()
        self.add_keypair()
        self.boot_instance()
        self.terminate_instance()
