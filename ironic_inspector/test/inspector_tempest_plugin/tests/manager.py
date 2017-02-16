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

import json
import os
import time

import six
import tempest
from tempest import config
from tempest.lib.common.api_version_utils import LATEST_MICROVERSION
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from ironic_inspector.test.inspector_tempest_plugin import exceptions
from ironic_inspector.test.inspector_tempest_plugin.services import \
    introspection_client
from ironic_tempest_plugin.tests.api.admin.api_microversion_fixture import \
    APIMicroversionFixture as IronicMicroversionFixture
from ironic_tempest_plugin.tests.scenario.baremetal_manager import \
    BaremetalProvisionStates
from ironic_tempest_plugin.tests.scenario.baremetal_manager import \
    BaremetalScenarioTest


CONF = config.CONF


class InspectorScenarioTest(BaremetalScenarioTest):
    """Provide harness to do Inspector scenario tests."""

    wait_provisioning_state_interval = 15

    credentials = ['primary', 'admin']

    ironic_api_version = LATEST_MICROVERSION

    @classmethod
    def setup_clients(cls):
        super(InspectorScenarioTest, cls).setup_clients()
        inspector_manager = introspection_client.Manager()
        cls.introspection_client = inspector_manager.introspection_client

    def setUp(self):
        super(InspectorScenarioTest, self).setUp()
        # we rely on the 'available' provision_state; using latest
        # microversion
        self.useFixture(IronicMicroversionFixture(self.ironic_api_version))
        self.flavor = self.baremetal_flavor()
        self.node_ids = {node['uuid'] for node in
                         self.node_filter(filter=lambda node:
                                          node['provision_state'] ==
                                          BaremetalProvisionStates.AVAILABLE)}
        self.rule_purge()

    def item_filter(self, list_method, show_method,
                    filter=lambda item: True, items=None):
        if items is None:
            items = [show_method(item['uuid']) for item in
                     list_method()]
        return [item for item in items if filter(item)]

    def node_list(self):
        return self.baremetal_client.list_nodes()[1]['nodes']

    def node_port_list(self, node_uuid):
        return self.baremetal_client.list_node_ports(node_uuid)[1]['ports']

    def node_update(self, uuid, patch):
        return self.baremetal_client.update_node(uuid, **patch)

    def node_show(self, uuid):
        return self.baremetal_client.show_node(uuid)[1]

    def node_delete(self, uuid):
        return self.baremetal_client.delete_node(uuid)

    def node_filter(self, filter=lambda node: True, nodes=None):
        return self.item_filter(self.node_list, self.node_show,
                                filter=filter, items=nodes)

    def node_set_power_state(self, uuid, state):
        self.baremetal_client.set_node_power_state(uuid, state)

    def node_set_provision_state(self, uuid, state):
        self.baremetal_client.set_node_provision_state(self, uuid, state)

    def hypervisor_stats(self):
        return (self.admin_manager.hypervisor_client.
                show_hypervisor_statistics())

    def server_show(self, uuid):
        self.servers_client.show_server(uuid)

    def rule_purge(self):
        self.introspection_client.purge_rules()

    def rule_import(self, rule_path):
        with open(rule_path, 'r') as fp:
            rules = json.load(fp)
        self.introspection_client.create_rules(rules)

    def rule_import_from_dict(self, rules):
        self.introspection_client.create_rules(rules)

    def introspection_status(self, uuid):
        return self.introspection_client.get_status(uuid)[1]

    def introspection_data(self, uuid):
        return self.introspection_client.get_data(uuid)[1]

    def introspection_start(self, uuid):
        return self.introspection_client.start_introspection(uuid)

    def introspection_abort(self, uuid):
        return self.introspection_client.abort_introspection(uuid)

    def baremetal_flavor(self):
        flavor_id = CONF.compute.flavor_ref
        flavor = self.flavors_client.show_flavor(flavor_id)['flavor']
        flavor['properties'] = self.flavors_client.list_flavor_extra_specs(
            flavor_id)['extra_specs']
        return flavor

    def get_rule_path(self, rule_file):
        base_path = os.path.split(
            os.path.dirname(os.path.abspath(__file__)))[0]
        base_path = os.path.split(base_path)[0]
        return os.path.join(base_path, "inspector_tempest_plugin",
                            "rules", rule_file)

    def boot_instance(self):
        return super(InspectorScenarioTest, self).boot_instance()

    def terminate_instance(self, instance):
        return super(InspectorScenarioTest, self).terminate_instance(instance)

    def wait_for_node(self, node_name):
        def check_node():
            try:
                self.node_show(node_name)
            except lib_exc.NotFound:
                return False
            return True

        if not test_utils.call_until_true(
                check_node,
                duration=CONF.baremetal_introspection.discovery_timeout,
                sleep_for=20):
            msg = ("Timed out waiting for node %s " % node_name)
            raise lib_exc.TimeoutException(msg)

        inspected_node = self.node_show(self.node_info['name'])
        self.wait_for_introspection_finished(inspected_node['uuid'])

    # TODO(aarefiev): switch to call_until_true
    def wait_for_introspection_finished(self, node_ids):
        """Waits for introspection of baremetal nodes to finish.

        """
        if isinstance(node_ids, six.text_type):
            node_ids = [node_ids]
        start = int(time.time())
        not_introspected = {node_id for node_id in node_ids}

        while not_introspected:
            time.sleep(CONF.baremetal_introspection.introspection_sleep)
            for node_id in node_ids:
                status = self.introspection_status(node_id)
                if status['finished']:
                    if status['error']:
                        message = ('Node %(node_id)s introspection failed '
                                   'with %(error)s.' %
                                   {'node_id': node_id,
                                    'error': status['error']})
                        raise exceptions.IntrospectionFailed(message)
                    not_introspected = not_introspected - {node_id}

            if (int(time.time()) - start >=
                    CONF.baremetal_introspection.introspection_timeout):
                message = ('Introspection timed out for nodes: %s' %
                           not_introspected)
                raise exceptions.IntrospectionTimeout(message)

    def wait_for_nova_aware_of_bvms(self):
        start = int(time.time())
        while True:
            time.sleep(CONF.baremetal_introspection.hypervisor_update_sleep)
            stats = self.hypervisor_stats()
            expected_cpus = self.baremetal_flavor()['vcpus']
            if int(stats['hypervisor_statistics']['vcpus']) >= expected_cpus:
                break

            timeout = CONF.baremetal_introspection.hypervisor_update_timeout
            if (int(time.time()) - start >= timeout):
                message = (
                    'Timeout while waiting for nova hypervisor-stats: '
                    '%(stats)s required time (%(timeout)s s).' %
                    {'stats': stats,
                     'timeout': timeout})
                raise exceptions.HypervisorUpdateTimeout(message)

    def node_cleanup(self, node_id):
        if (self.node_show(node_id)['provision_state'] ==
           BaremetalProvisionStates.AVAILABLE):
            return
        # in case when introspection failed we need set provision state
        # to 'manage' to make it possible transit into 'provide' state
        if self.node_show(node_id)['provision_state'] == 'inspect failed':
            self.baremetal_client.set_node_provision_state(node_id, 'manage')

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

    def introspect_node(self, node_id, remove_props=True):
        if remove_props:
            # in case there are properties remove those
            patch = {('properties/%s' % key): None for key in
                     self.node_show(node_id)['properties']}
            # reset any previous rule result
            patch['extra/rule_success'] = None
            self.node_update(node_id, patch)

        self.baremetal_client.set_node_provision_state(node_id, 'manage')
        self.baremetal_client.set_node_provision_state(node_id, 'inspect')
        self.addCleanup(self.node_cleanup, node_id)
