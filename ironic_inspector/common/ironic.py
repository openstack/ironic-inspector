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

import socket
import urllib

import netaddr
import openstack
from openstack import exceptions as os_exc
from oslo_config import cfg
from oslo_utils import excutils
import tenacity

from ironic_inspector.common.i18n import _
from ironic_inspector.common import keystone
from ironic_inspector import utils

CONF = cfg.CONF
LOG = utils.getProcessingLogger(__name__)

# See https://docs.openstack.org/ironic/latest/contributor/states.html
VALID_STATES = frozenset(['enroll', 'manageable', 'inspecting', 'inspect wait',
                          'inspect failed'])

# States where an instance is deployed and an admin may be doing something.
VALID_ACTIVE_STATES = frozenset(['active', 'rescue'])

_IRONIC_SESSION = None
_CONNECTION = None


class NotFound(utils.Error):
    """Node not found in Ironic."""

    def __init__(self, node_ident, code=404, *args, **kwargs):
        msg = _('Node %s was not found in Ironic') % node_ident
        super(NotFound, self).__init__(msg, code, *args, **kwargs)


def _get_ironic_session():
    global _IRONIC_SESSION

    if not _IRONIC_SESSION:
        _IRONIC_SESSION = keystone.get_session('ironic')
    return _IRONIC_SESSION


def get_client(token=None):
    """Get an ironic client connection."""
    global _CONNECTION

    if _CONNECTION is None:
        try:
            session = _get_ironic_session()
            _CONNECTION = openstack.connection.Connection(
                session=session, oslo_conf=CONF)
        except Exception as exc:
            LOG.error('Failed to create an openstack connection: %s', exc)
            raise

    try:
        return _CONNECTION.baremetal
    except Exception as exc:
        with excutils.save_and_reraise_exception():
            LOG.error('Failed to connect to Ironic: %s', exc)
            # Force creating a new connection on the next retry
            try:
                _CONNECTION.close()
            except Exception as exc2:
                LOG.error('Unable to close an openstack connection, '
                          'a memory leak is possible. Error: %s', exc2)
            _CONNECTION = None


def reset_ironic_session():
    """Reset the global session variable.

    Mostly useful for unit tests.
    """
    global _IRONIC_SESSION, _CONNECTION
    _CONNECTION = _IRONIC_SESSION = None


def get_ipmi_address(node):
    """Get the BMC address defined in node.driver_info dictionary

    Possible names of BMC address value examined in order of list
    ['ipmi_address'] + CONF.ipmi_address_fields. The value could
    be an IP address or a hostname. DNS lookup performed for the
    first non empty value.

    The first valid BMC address value returned along with
    it's v4 and v6 IP addresses.

    :param node: Node object with defined driver_info dictionary
    :return: tuple (ipmi_address, ipv4_address, ipv6_address)
    """
    none_address = None, None, None
    ipmi_fields = ['ipmi_address'] + CONF.ipmi_address_fields
    # NOTE(sambetts): IPMI Address is useless to us if bridging is enabled so
    # just ignore it and return None
    if node.driver_info.get("ipmi_bridging", "no") != "no":
        return none_address
    for name in ipmi_fields:
        value = node.driver_info.get(name)
        if not value:
            continue

        ipv4 = None
        ipv6 = None
        if '//' in value:
            url = urllib.parse.urlparse(value)
            value = url.hostname

        # Strip brackets in case used on IPv6 address.
        value = value.strip('[').strip(']')

        try:
            addrinfo = socket.getaddrinfo(value, None, 0, 0, socket.SOL_TCP)
            for family, socket_type, proto, canon_name, sockaddr in addrinfo:
                ip = sockaddr[0]
                if netaddr.IPAddress(ip).is_loopback():
                    LOG.warning('Ignoring loopback BMC address %s', ip,
                                node_info=node)
                elif family == socket.AF_INET:
                    ipv4 = ip
                elif family == socket.AF_INET6:
                    ipv6 = ip
        except socket.gaierror:
            LOG.warning('Failed to resolve the hostname (%s)'
                        ' for node %s', value, node.id, node_info=node)

        return (value, ipv4, ipv6) if ipv4 or ipv6 else none_address
    return none_address


def check_provision_state(node):
    """Sanity checks the provision state of the node.

    :param node: An API client returned node object describing
                 the baremetal node according to ironic's node
                 data model.
    :returns: None if no action is to be taken, True if the
              power node state should not be modified.
    :raises: Error on an invalid state being detected.
    """
    state = node.provision_state.lower()
    if state not in VALID_STATES:
        if (CONF.processing.permit_active_introspection
                and state in VALID_ACTIVE_STATES):
            # Hey, we can leave the power on! Lets return
            # True to let the caller know.
            return True

        msg = _('Invalid provision state for introspection: '
                '"%(state)s", valid states are "%(valid)s"')
        raise utils.Error(msg % {'state': state,
                                 'valid': list(VALID_STATES)},
                          node_info=node)


def capabilities_to_dict(caps):
    """Convert the Node's capabilities into a dictionary."""
    if not caps:
        return {}
    return dict([key.split(':', 1) for key in caps.split(',')])


def dict_to_capabilities(caps_dict):
    """Convert a dictionary into a string with the capabilities syntax."""
    return ','.join(["%s:%s" % (key, value)
                     for key, value in caps_dict.items()
                     if value is not None])


def get_node(node_id, ironic=None, **kwargs):
    """Get a node from Ironic.

    :param node_id: node UUID or name.
    :param ironic: ironic client instance.
    :param kwargs: arguments to pass to Ironic client.
    :raises: Error on failure
    """
    ironic = ironic if ironic is not None else get_client()

    try:
        node = ironic.get_node(node_id, **kwargs)
    except os_exc.ResourceNotFound:
        raise NotFound(node_id)
    except os_exc.BadRequestException as exc:
        raise utils.Error(_("Cannot get node %(node)s: %(exc)s") %
                          {'node': node_id, 'exc': exc})
    return node


@tenacity.retry(
    retry=tenacity.retry_if_exception_type(os_exc.SDKException),
    stop=tenacity.stop_after_attempt(5),
    wait=tenacity.wait_fixed(1),
    reraise=True)
def call_with_retries(func, *args, **kwargs):
    """Call an ironic client function retrying all errors.

    If an ironic client exception is raised, try calling the func again,
    at most 5 times, waiting 1 sec between each call. If on the 5th attempt
    the func raises again, the exception is propagated to the caller.
    """
    return func(*args, **kwargs)


def lookup_node_by_macs(macs, introspection_data=None,
                        ironic=None, fail=False):
    """Find a node by its MACs."""
    if ironic is None:
        ironic = get_client()

    nodes = set()
    for mac in macs:
        ports = ironic.ports(address=mac, fields=["uuid", "node_uuid"])
        ports = list(ports)
        if not ports:
            continue
        elif fail:
            raise utils.Error(
                _('Port %(mac)s already exists, uuid: %(uuid)s') %
                {'mac': mac, 'uuid': ports[0].id}, data=introspection_data)
        else:
            nodes.update(p.node_id for p in ports)

    if len(nodes) > 1:
        raise utils.Error(_('MAC addresses %(macs)s correspond to more than '
                            'one node: %(nodes)s') %
                          {'macs': ', '.join(macs),
                           'nodes': ', '.join(nodes)},
                          data=introspection_data)

    elif nodes:
        return nodes.pop()


def lookup_node_by_bmc_addresses(addresses, introspection_data=None,
                                 ironic=None, fail=False):
    """Find a node by its BMC address."""
    if ironic is None:
        ironic = get_client()

    # FIXME(aarefiev): it's not effective to fetch all nodes, and may
    #                  impact on performance on big clusters
    # TODO(TheJulia): We should likely first loop through nodes being
    #                 inspected, i.e. inspect wait, and then fallback
    #                 to the rest of the physical nodes so we limit
    #                 overall-impact of the operation.
    nodes = ironic.nodes(fields=('uuid', 'driver_info'), limit=None)
    found = set()
    for node in nodes:
        bmc_address, bmc_ipv4, bmc_ipv6 = get_ipmi_address(node)
        for addr in addresses:
            if addr not in (bmc_ipv4, bmc_ipv6):
                continue
            elif fail:
                raise utils.Error(
                    _('Node %(uuid)s already has BMC address %(addr)s') %
                    {'addr': addr, 'uuid': node.id},
                    data=introspection_data)
            else:
                found.add(node.id)

    if len(found) > 1:
        raise utils.Error(_('BMC addresses %(addr)s correspond to more than '
                            'one node: %(nodes)s') %
                          {'addr': ', '.join(addresses),
                           'nodes': ', '.join(found)},
                          data=introspection_data)
    elif found:
        return found.pop()


def lookup_node(macs=None, bmc_addresses=None, introspection_data=None,
                ironic=None):
    """Lookup a node in the ironic database."""
    node = node2 = None

    if macs:
        node = lookup_node_by_macs(macs, ironic=ironic)
    if bmc_addresses:
        node2 = lookup_node_by_bmc_addresses(bmc_addresses, ironic=ironic)

    if node and node2 and node != node2:
        raise utils.Error(_('MAC addresses %(mac)s and BMC addresses %(addr)s '
                            'correspond to different nodes: %(node1)s and '
                            '%(node2)s') %
                          {'mac': ', '.join(macs),
                           'addr': ', '.join(bmc_addresses),
                           'node1': node, 'node2': node2})

    return node or node2
