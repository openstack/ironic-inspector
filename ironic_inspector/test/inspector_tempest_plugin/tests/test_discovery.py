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

import six

from ironic_tempest_plugin.tests.scenario import baremetal_manager
from tempest import config
from tempest.lib import decorators
from tempest import test  # noqa

from ironic_inspector.test.inspector_tempest_plugin.tests import manager

CONF = config.CONF

ProvisionStates = baremetal_manager.BaremetalProvisionStates


class InspectorDiscoveryTest(manager.InspectorScenarioTest):
    @classmethod
    def skip_checks(cls):
        super(InspectorDiscoveryTest, cls).skip_checks()
        if not CONF.baremetal_introspection.auto_discovery_feature:
            msg = ("Please, provide a value for node_not_found_hook in "
                   "processing section of inspector.conf for enable "
                   "auto-discovery feature.")
            raise cls.skipException(msg)

    def setUp(self):
        super(InspectorDiscoveryTest, self).setUp()

        discovered_node = self._get_discovery_node()
        self.node_info = self._get_node_info(discovered_node)

        rule = self._generate_discovery_rule(self.node_info)

        self.rule_import_from_dict(rule)
        self.addCleanup(self.rule_purge)

    def _get_node_info(self, node_uuid):
        node = self.node_show(node_uuid)
        ports = self.node_port_list(node_uuid)
        node['port_macs'] = [port['address'] for port in ports]
        return node

    def _get_discovery_node(self):
        nodes = self.node_list()

        discovered_node = None
        for node in nodes:
            if (node['provision_state'] == ProvisionStates.AVAILABLE or
                    node['provision_state'] == ProvisionStates.ENROLL or
                    node['provision_state'] is ProvisionStates.NOSTATE):
                discovered_node = node['uuid']
                break

        self.assertIsNotNone(discovered_node)
        return discovered_node

    def _generate_discovery_rule(self, node):
        rule = dict()
        rule["description"] = "Node %s discovery rule" % node['name']
        rule["actions"] = [
            {"action": "set-attribute", "path": "/name",
             "value": "%s" % node['name']},
            {"action": "set-attribute", "path": "/driver",
             "value": "%s" % node['driver']},
        ]

        for key, value in node['driver_info'].items():
            rule["actions"].append(
                {"action": "set-attribute", "path": "/driver_info/%s" % key,
                 "value": "%s" % value})
        rule["conditions"] = [
            {"op": "eq", "field": "data://auto_discovered", "value": True}
        ]
        return rule

    def verify_node_introspection_data(self, node):
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

    def verify_node_driver_info(self, node_info, inspected_node):
        for key in node_info['driver_info']:
            self.assertEqual(six.text_type(node_info['driver_info'][key]),
                             inspected_node['driver_info'].get(key))

    @decorators.idempotent_id('dd3abe5e-0d23-488d-bb4e-344cdeff7dcb')
    def test_bearmetal_auto_discovery(self):
        """This test case follows this set of operations:

           * Choose appropriate node, based on provision state;
           * Get node info;
           * Generate discovery rule;
           * Delete discovered node from ironic;
           * Start baremetal vm via virsh;
           * Wating for node introspection;
           * Verify introspected node.
        """
        # NOTE(aarefiev): workaround for infra, 'tempest' user doesn't
        # have virsh privileges, so lets power on the node via ironic
        # and then delete it. Because of node is blacklisted in inspector
        # we can't just power on it, therefor start introspection is used
        # to whitelist discovered node first.
        self.baremetal_client.set_node_provision_state(
            self.node_info['uuid'], 'manage')
        self.introspection_start(self.node_info['uuid'])
        self.wait_power_state(
            self.node_info['uuid'],
            baremetal_manager.BaremetalPowerStates.POWER_ON)
        self.node_delete(self.node_info['uuid'])

        self.wait_for_node(self.node_info['name'])

        inspected_node = self.node_show(self.node_info['name'])
        self.verify_node_flavor(inspected_node)
        self.verify_node_introspection_data(inspected_node)
        self.verify_node_driver_info(self.node_info, inspected_node)
        self.assertEqual(ProvisionStates.ENROLL,
                         inspected_node['provision_state'])
