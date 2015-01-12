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

"""Handling discovery request."""

import logging

import eventlet
from ironicclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd import utils


LOG = logging.getLogger("ironic_discoverd.discover")
# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'managed', 'inspecting'}
VALID_POWER_STATES = {'power off'}


def introspect(uuid):
    """Initiate hardware properties introspection for a given node.

    :param uuid: node uuid
    :raises: DiscoveryFailed
    """
    ironic = utils.get_client()

    try:
        node = ironic.node.get(uuid)
    except exceptions.NotFound:
        LOG.error('Node %s cannot be found', uuid)
        raise utils.DiscoveryFailed("Cannot find node %s" % uuid, code=404)
    except exceptions.HttpError as exc:
        LOG.exception('Cannot get node %s', uuid)
        raise utils.DiscoveryFailed("Cannot get node %s: %s" % (uuid, exc))

    if (node.extra.get('ipmi_setup_credentials') and not
            conf.getboolean('discoverd', 'enable_setting_ipmi_credentials')):
        msg = 'IPMI credentials setup is disabled in configuration'
        LOG.error(msg)
        raise utils.DiscoveryFailed(msg)

    if not node.maintenance:
        provision_state = node.provision_state
        if provision_state and provision_state.lower() not in VALID_STATES:
            msg = ('Refusing to discoverd node %s with provision state "%s" '
                   'and maintenance mode off')
            LOG.error(msg, node.uuid, provision_state)
            raise utils.DiscoveryFailed(msg % (node.uuid, provision_state))

        power_state = node.power_state
        if power_state and power_state.lower() not in VALID_POWER_STATES:
            msg = ('Refusing to discover node %s with power state "%s" '
                   'and maintenance mode off')
            LOG.error(msg, node.uuid, power_state)
            raise utils.DiscoveryFailed(msg % (node.uuid, power_state))
    else:
        LOG.info('Node %s is in maintenance mode, skipping power and provision'
                 ' states check')

    if not node.extra.get('ipmi_setup_credentials'):
        validation = utils.retry_on_conflict(ironic.node.validate, node.uuid)
        if not validation.power['result']:
            LOG.error('Failed validation of power interface for node %s, '
                      'reason: %s', node.uuid, validation.power['reason'])
            raise utils.DiscoveryFailed(
                'Failed validation of power interface for node %s' % node.uuid)

    eventlet.greenthread.spawn_n(_background_start_discover, ironic, node)


def _background_start_discover(ironic, node):
    patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'}]
    utils.retry_on_conflict(ironic.node.update, node.uuid, patch)

    # TODO(dtantsur): pagination
    macs = [p.address for p in ironic.node.list_ports(node.uuid, limit=0)]
    node_cache.add_node(node.uuid,
                        bmc_address=node.driver_info.get('ipmi_address'),
                        mac=macs)

    if macs:
        LOG.info('Whitelisting MAC\'s %s for node %s on the firewall',
                 macs, node.uuid)
        firewall.update_filters(ironic)

    if not node.extra.get('ipmi_setup_credentials'):
        try:
            utils.retry_on_conflict(ironic.node.set_boot_device,
                                    node.uuid, 'pxe', persistent=False)
        except Exception as exc:
            LOG.warning('Failed to set boot device to PXE for node %s: %s',
                        node.uuid, exc)

        try:
            utils.retry_on_conflict(ironic.node.set_power_state,
                                    node.uuid, 'reboot')
        except Exception as exc:
            LOG.error('Failed to power on node %s, check it\'s power '
                      'management configuration:\n%s', node.uuid, exc)
    else:
        LOG.info('Discovery environment is ready for node %s, '
                 'manual power on is required within %d seconds',
                 node.uuid, conf.getint('discoverd', 'timeout'))
