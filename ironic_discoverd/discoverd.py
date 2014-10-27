import logging
import time

import eventlet

from ironicclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import utils


LOG = logging.getLogger("discoverd")
ALLOW_SEARCH_BY_MAC = True


def process(node_info):
    """Process data from discovery ramdisk."""
    if node_info.get('error'):
        LOG.error('Error happened during discovery: %s',
                  node_info['error'])
        return

    compat = conf.getboolean('discoverd', 'ports_for_inactive_interfaces')
    if 'interfaces' not in node_info and 'macs' in node_info:
        LOG.warning('Using "macs" field is deprecated, please '
                    'update your discovery ramdisk')
        node_info['interfaces'] = {'dummy%d' % i: {'mac': m}
                                   for i, m in enumerate(node_info['macs'])}
        compat = True

    keys = ('cpus', 'cpu_arch', 'memory_mb', 'local_gb', 'interfaces')
    missing = [key for key in keys if not node_info.get(key)]
    if missing:
        LOG.error('The following required parameters are missing: %s',
                  missing)
        return

    LOG.info('Discovery data received from node with BMC '
             '%(ipmi_address)s: CPUs: %(cpus)s %(cpu_arch)s, '
             'memory %(memory_mb)s MiB, disk %(local_gb)s GiB, '
             'interfaces %(interfaces)s',
             dict((key, node_info.get(key))
                  for key in keys + ('ipmi_address',)))

    valid_interfaces = {
        n: iface for n, iface in node_info['interfaces'].items()
        if utils.is_valid_mac(iface['mac']) and (compat or iface.get('ip'))
    }
    valid_macs = [iface['mac'] for iface in valid_interfaces.values()]
    if valid_interfaces != node_info['interfaces']:
        LOG.warning(
            'The following interfaces were invalid or not eligible in '
            'discovery data for node with BMC %(ipmi_address)s and were '
            'excluded: %(invalid)s',
            {'invalid': {n: iface
                         for n, iface in node_info['interfaces'].items()
                         if n not in valid_interfaces},
             'ipmi_address': node_info.get('ipmi_address')})
        LOG.info('Eligible interfaces are %s', valid_interfaces)

    ironic = utils.get_client()
    bmc_known = bool(node_info.get('ipmi_address'))
    if bmc_known:
        # TODO(dtantsur): bulk loading
        nodes = ironic.node.list(maintenance=True, limit=0,
                                 sort_key='created_at',
                                 sort_dir='desc', detail=True)
        address = node_info['ipmi_address']
        for node in nodes:
            if node.driver_info.get('ipmi_address') == address:
                break
        else:
            LOG.error('Unable to find node with ipmi_address %s',
                      node_info['ipmi_address'])
            return
    elif ALLOW_SEARCH_BY_MAC:
        # In case of testing with vms and pxe_ssh driver
        LOG.warning('No BMC address provided, trying to use MAC '
                    'addresses for finding node')
        port = None
        for mac in valid_macs:
            try:
                port = ironic.port.get_by_address(mac)
            except exceptions.NotFound:
                continue
            else:
                break

        if port is not None:
            try:
                node = ironic.node.get(port.node_uuid)
            except exceptions.NotFound:
                node = None

        if port is None or node is None:
            LOG.error('Unable to find node with macs %s',
                      valid_macs)
            return
    else:
        LOG.error('No ipmi_address provided and searching by MAC is not '
                  'allowed')
        return

    if not node.extra.get('on_discovery'):
        LOG.error('Node is not on discovery, cannot proceed')
        return

    patch = [{'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
             {'op': 'remove', 'path': '/extra/on_discovery'}]
    existing = node.properties
    for key in ('cpus', 'cpu_arch', 'memory_mb', 'local_gb'):
        if not existing.get(key):
            patch.append({'op': 'add', 'path': '/properties/%s' % key,
                          'value': str(node_info[key])})
    ironic.node.update(node.uuid, patch)

    for mac in valid_macs:
        try:
            ironic.port.create(node_uuid=node.uuid, address=mac)
        except exceptions.Conflict:
            LOG.warning('MAC %(mac)s appeared in discovery data for '
                        'node %(node)s, but already exists in '
                        'database - skipping',
                        {'mac': mac, 'node': node.uuid})

    LOG.info('Node %s was updated with data from discovery process, forcing '
             'power off', node.uuid)

    firewall.unwhitelist_macs(valid_macs)
    firewall.update_filters(ironic)

    try:
        ironic.node.set_power_state(node.uuid, 'off')
    except Exception as exc:
        LOG.error('Failed to power off node %s, check it\'s power '
                  'management configuration:\n%s', node.uuid, exc)


class DiscoveryFailed(Exception):
    def __init__(self, msg, code=400):
        super(DiscoveryFailed, self).__init__(msg)
        self.http_code = code


def discover(uuids):
    """Initiate discovery for given node uuids."""
    if not uuids:
        raise DiscoveryFailed("No nodes to discover")

    ironic = utils.get_client()
    LOG.debug('Validating nodes %s', uuids)
    nodes = []
    for uuid in uuids:
        try:
            node = ironic.node.get(uuid)
        except exceptions.NotFound:
            LOG.error('Node %s cannot be found', uuid)
            raise DiscoveryFailed("Cannot find node %s" % uuid, code=404)
        except exceptions.HttpError as exc:
            LOG.exception('Cannot get node %s', uuid)
            raise DiscoveryFailed("Cannot get node %s: %s" % (uuid, exc))

        _validate(ironic, node)

        if node.extra.get('on_discovery'):
            LOG.warning('Node %s seems to be on discovery already', node.uuid)

        nodes.append(node)

    LOG.info('Proceeding with discovery on nodes %s', [n.uuid for n in nodes])
    eventlet.greenthread.spawn_n(_background_discover, ironic, nodes)


def _validate(ironic, node):
    if node.instance_uuid:
        LOG.error('Refusing to discover node %s with assigned instance_uuid',
                  node.uuid)
        raise DiscoveryFailed(
            'Refusing to discover node %s with assigned instance uuid' %
            node.uuid)

    power_state = node.power_state
    if (not node.maintenance and power_state is not None
            and power_state.lower() != 'power off'):
        LOG.error('Refusing to discover node %s with power_state "%s" '
                  'and maintenance mode off',
                  node.uuid, power_state)
        raise DiscoveryFailed(
            'Refusing to discover node %s with power state "%s" and '
            'maintenance mode off' %
            (node.uuid, power_state))

    validation = ironic.node.validate(node.uuid)
    if not validation.power['result']:
        LOG.error('Failed validation of power interface for node %s, '
                  'reason: %s', node.uuid, validation.power['reason'])
        raise DiscoveryFailed('Failed validation of power interface for '
                              'node %s' % node.uuid)


def _background_discover(ironic, nodes):
    patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'},
             {'op': 'add', 'path': '/extra/discovery_timestamp',
              'value': str(time.time())}]
    for node in nodes:
        node_patch = []
        if not node.maintenance:
            LOG.warning('Node %s will be put in maintenance mode', node.uuid)
            node_patch.append(
                {'op': 'replace', 'path': '/maintenance', 'value': 'true'})

        ironic.node.update(node.uuid, patch + node_patch)

    to_exclude = set()
    for node in nodes:
        # TODO(dtantsur): pagination
        ports = ironic.node.list_ports(node.uuid, limit=0)
        to_exclude.update(p.address for p in ports)

    if to_exclude:
        LOG.info('Whitelisting MAC\'s %s in the firewall', to_exclude)
        firewall.whitelist_macs(to_exclude)
        firewall.update_filters(ironic)

    for node in nodes:
        try:
            ironic.node.set_power_state(node.uuid, 'reboot')
        except Exception as exc:
            LOG.error('Failed to power on node %s, check it\'s power '
                      'management configuration:\n%s', node.uuid, exc)
