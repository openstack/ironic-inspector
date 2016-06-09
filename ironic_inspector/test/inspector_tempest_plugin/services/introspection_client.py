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

from ironic_tempest_plugin.services.baremetal import base
from tempest import clients
from tempest.common import credentials_factory as common_creds
from tempest import config


CONF = config.CONF
ADMIN_CREDS = common_creds.get_configured_admin_credentials()


class Manager(clients.Manager):
    def __init__(self,
                 credentials=ADMIN_CREDS,
                 service=None,
                 api_microversions=None):
        super(Manager, self).__init__(credentials, service)
        self.introspection_client = BaremetalIntrospectionClient(
            self.auth_provider,
            CONF.baremetal_introspection.catalog_type,
            CONF.identity.region,
            endpoint_type=CONF.baremetal_introspection.endpoint_type,
            **self.default_params_with_timeout_values)


class BaremetalIntrospectionClient(base.BaremetalClient):
    """Base Tempest REST client for Ironic Inspector API v1."""
    version = '1'
    uri_prefix = 'v1'

    @base.handle_errors
    def purge_rules(self):
        """Purge all existing rules."""
        return self._delete_request('rules', uuid=None)

    @base.handle_errors
    def import_rule(self, rule_path):
        """Import introspection rules from a json file."""
        with open(rule_path, 'r') as fp:
            rules = json.load(fp)
            if not isinstance(rules, list):
                rules = [rules]

        for rule in rules:
            self._create_request('rules', rule)

    @base.handle_errors
    def get_status(self, uuid):
        """Get introspection status for a node."""
        return self._show_request('introspection', uuid=uuid)

    @base.handle_errors
    def get_data(self, uuid):
        """Get introspection data for a node."""
        return self._show_request('introspection', uuid=uuid,
                                  uri='/%s/introspection/%s/data' %
                                      (self.uri_prefix, uuid))
