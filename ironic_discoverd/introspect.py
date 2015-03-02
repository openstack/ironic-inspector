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

"""Handling introspection request."""

import logging

import eventlet
from ironicclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd import utils


LOG = logging.getLogger("ironic_discoverd.introspect")
# See http://specs.openstack.org/openstack/ironic-specs/specs/kilo/new-ironic-state-machine.html  # noqa
VALID_STATES = {'enroll', 'manageable', 'inspecting'}


def introspect(uuid, setup_ipmi_credentials=False):
    """Initiate hardware properties introspection for a given node.

    :param uuid: node uuid
    :raises: Error
    """
    ironic = utils.get_client()

    try:
        node = ironic.node.get(uuid)
    except exceptions.NotFound:
        raise utils.Error("Cannot find node %s" % uuid, code=404)
    except exceptions.HttpError as exc:
        raise utils.Error("Cannot get node %s: %s" % (uuid, exc))

    if (setup_ipmi_credentials and not
            conf.getboolean('discoverd', 'enable_setting_ipmi_credentials')):
        raise utils.Error(
            'IPMI credentials setup is disabled in configuration')

    if not node.maintenance:
        provision_state = node.provision_state
        if provision_state and provision_state.lower() not in VALID_STATES:
            msg = ('Refusing to introspect node %s with provision state "%s" '
                   'and maintenance mode off')
            raise utils.Error(msg % (node.uuid, provision_state))
    else:
        LOG.info('Node %s is in maintenance mode, skipping power and provision'
                 ' states check')

    if not setup_ipmi_credentials:
        validation = utils.retry_on_conflict(ironic.node.validate, node.uuid)
        if not validation.power['result']:
            msg = ('Failed validation of power interface for node %s, '
                   'reason: %s')
            raise utils.Error(msg % (node.uuid, validation.power['reason']))

    eventlet.greenthread.spawn_n(_background_start_discover, ironic, node,
                                 setup_ipmi_credentials=setup_ipmi_credentials)


def _get_ipmi_address(node):
    # All these are kind-of-ipmi
    for name in ('ipmi_address', 'ilo_address', 'drac_host'):
        value = node.driver_info.get(name)
        if value:
            return value


def _background_start_discover(ironic, node, setup_ipmi_credentials):
    patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'}]
    utils.retry_on_conflict(ironic.node.update, node.uuid, patch)

    # TODO(dtantsur): pagination
    macs = [p.address for p in ironic.node.list_ports(node.uuid, limit=0)]
    cached_node = node_cache.add_node(node.uuid,
                                      bmc_address=_get_ipmi_address(node),
                                      mac=macs)
    cached_node.set_option('setup_ipmi_credentials', setup_ipmi_credentials)
    try:
        _prepare_for_pxe(ironic, cached_node, macs, setup_ipmi_credentials)
    except utils.Error as exc:
        cached_node.finished(error=str(exc))
    except Exception as exc:
        msg = 'Unexpected exception during preparing for PXE boot'
        LOG.exception(msg)
        cached_node.finished(error=msg)


def _prepare_for_pxe(ironic, cached_node, macs, setup_ipmi_credentials):
    if macs:
        LOG.info('Whitelisting MAC\'s %s for node %s on the firewall',
                 macs, cached_node.uuid)
        firewall.update_filters(ironic)

    if not setup_ipmi_credentials:
        try:
            utils.retry_on_conflict(ironic.node.set_boot_device,
                                    cached_node.uuid, 'pxe', persistent=False)
        except Exception as exc:
            LOG.warning('Failed to set boot device to PXE for node %s: %s',
                        cached_node.uuid, exc)

        try:
            utils.retry_on_conflict(ironic.node.set_power_state,
                                    cached_node.uuid, 'reboot')
        except Exception as exc:
            raise utils.Error('Failed to power on node %s, check it\'s power '
                              'management configuration:\n%s'
                              % (cached_node.uuid, exc))
    else:
        LOG.info('Introspection environment is ready for node %s, '
                 'manual power on is required within %d seconds',
                 cached_node.uuid, conf.getint('discoverd', 'timeout'))
