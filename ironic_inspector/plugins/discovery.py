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

"""Enroll node not found hook hook."""

from oslo_config import cfg

from ironic_inspector.common.i18n import _, _LW
from ironic_inspector.common import ironic as ir_utils
from ironic_inspector import node_cache
from ironic_inspector import utils


DISCOVERY_OPTS = [
    cfg.StrOpt('enroll_node_driver',
               default='fake',
               help='The name of the Ironic driver used by the enroll '
                    'hook when creating a new node in Ironic.'),
]


def list_opts():
    return [
        ('discovery', DISCOVERY_OPTS)
    ]

CONF = cfg.CONF
CONF.register_opts(DISCOVERY_OPTS, group='discovery')

LOG = utils.getProcessingLogger(__name__)


def _extract_node_driver_info(introspection_data):
    node_driver_info = {}
    ipmi_address = utils.get_ipmi_address_from_data(introspection_data)
    if ipmi_address:
        node_driver_info['ipmi_address'] = ipmi_address
    else:
        LOG.warning(_LW('No BMC address provided, discovered node will be '
                        'created without ipmi address'))
    return node_driver_info


def _check_existing_nodes(introspection_data, node_driver_info, ironic):
    macs = utils.get_valid_macs(introspection_data)
    if macs:
        # verify existing ports
        for mac in macs:
            ports = ironic.port.list(address=mac)
            if not ports:
                continue
            raise utils.Error(
                _('Port %(mac)s already exists, uuid: %(uuid)s') %
                {'mac': mac, 'uuid': ports[0].uuid}, data=introspection_data)
    else:
        LOG.warning(_LW('No suitable interfaces found for discovered node. '
                        'Check that validate_interfaces hook is listed in '
                        '[processing]default_processing_hooks config option'))

    # verify existing node with discovered ipmi address
    ipmi_address = node_driver_info.get('ipmi_address')
    if ipmi_address:
        # FIXME(aarefiev): it's not effective to fetch all nodes, and may
        #                  impact on performance on big clusters
        nodes = ironic.node.list(fields=('uuid', 'driver_info'), limit=0)
        for node in nodes:
            if ipmi_address == ir_utils.get_ipmi_address(node):
                raise utils.Error(
                    _('Node %(uuid)s already has BMC address '
                      '%(ipmi_address)s, not enrolling') %
                    {'ipmi_address': ipmi_address, 'uuid': node.uuid},
                    data=introspection_data)


def enroll_node_not_found_hook(introspection_data, **kwargs):
    node_attr = {}
    ironic = ir_utils.get_client()

    node_driver_info = _extract_node_driver_info(introspection_data)
    node_attr['driver_info'] = node_driver_info

    node_driver = CONF.discovery.enroll_node_driver

    _check_existing_nodes(introspection_data, node_driver_info, ironic)
    LOG.debug('Creating discovered node with driver %(driver)s and '
              'attributes: %(attr)s',
              {'driver': node_driver, 'attr': node_attr},
              data=introspection_data)
    # NOTE(aarefiev): This flag allows to distinguish enrolled manually
    # and auto-discovered nodes in the introspection rules.
    introspection_data['auto_discovered'] = True
    return node_cache.create_node(node_driver, ironic=ironic, **node_attr)
