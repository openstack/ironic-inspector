import ConfigParser
import logging
import re
from subprocess import call, check_call

from ironicclient import client, exceptions
from keystoneclient.v2_0 import client as keystone


LOG = logging.getLogger("discoverd")
ALLOW_SEARCH_BY_MAC = True
CONF = ConfigParser.ConfigParser(
    defaults={'debug': 'false',
              'listen_address': '0.0.0.0',
              'listen_port': '5050',
              'dnsmasq_interface': 'br-ctlplane',
              'authenticate': 'true'})
OS_ARGS = ('os_password', 'os_username', 'os_auth_url', 'os_tenant_name')


def get_client():
    args = dict((k, CONF.get('discoverd', k)) for k in OS_ARGS)
    return client.get_client(1, **args)


def get_keystone(token):
    return keystone.Client(token=token, auth_url=CONF.get('discoverd',
                                                          'os_auth_url'))


def is_valid_mac(address):
    m = "[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
    return (isinstance(address, (str, unicode))
            and re.match(m, address.lower()))


def process(node_info):
    """Process data from discovery ramdisk."""
    if node_info.get('error'):
        LOG.error('Error happened during discovery: %s',
                  node_info['error'])
        return

    keys = ('cpus', 'cpu_arch', 'memory_mb', 'local_gb', 'macs')
    missing = [key for key in keys if not node_info.get(key)]
    if missing:
        LOG.error('The following required parameters are missing: %s',
                  missing)
        return

    valid_macs = [mac.lower() for mac in node_info['macs']
                  if is_valid_mac(mac)]
    if valid_macs != node_info['macs']:
        LOG.warn('The following MACs were invalid in discovery data '
                 'for node with BMC %(ipmi_address)s and were '
                 'excluded: %(invalid)s',
                 {'invalid': set(node_info['macs']) - set(valid_macs),
                  'ipmi_address': node_info.get('ipmi_address')})

    LOG.info('Discovery data received from node with BMC '
             '%(ipmi_address)s: CPUs: %(cpus)s %(cpu_arch)s, '
             'memory %(memory_mb)s MiB, disk %(local_gb)s GiB, '
             'macs %(macs)s',
             dict((key, node_info.get(key))
                  for key in keys + ('ipmi_address',)))

    ironic = get_client()
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
        LOG.warn('No BMC address provided, trying to use MAC '
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

    Firewall.unwhitelist_macs(valid_macs)
    Firewall.update_filters(ironic)

    ironic.node.set_power_state(node.uuid, 'off')


class Firewall(object):
    MACS_DISCOVERY = set()
    NEW_CHAIN = 'discovery_temp'
    CHAIN = 'discovery'
    INTERFACE = None

    @staticmethod
    def _iptables(*args, **kwargs):
        cmd = ('iptables',) + args
        LOG.debug('Running iptables %s', args)
        if kwargs.pop('ignore', False):
            if call(cmd, **kwargs):
                LOG.warn('iptables failed: %s', args)
                return False
            else:
                return True
        else:
            try:
                return check_call(cmd, **kwargs)
            except Exception:
                LOG.error('iptables failed: %s', args)
                raise

    @classmethod
    def init(cls):
        cls.INTERFACE = CONF.get('discoverd', 'dnsmasq_interface')
        cls._iptables('-F', cls.NEW_CHAIN, ignore=True)
        cls._iptables('-X', cls.NEW_CHAIN, ignore=True)
        cls._iptables('-D', 'INPUT', '-i', cls.INTERFACE, '-p', 'udp',
                      '--dport', '67', '-j', cls.CHAIN,
                      ignore=True)  # may be missing on first run
        cls._iptables('-F', cls.CHAIN, ignore=True)
        cls._iptables('-X', cls.CHAIN, ignore=True)
        # Code expects it to exist
        cls._iptables('-N', cls.CHAIN)

    @classmethod
    def whitelist_macs(cls, macs):
        cls.MACS_DISCOVERY.update(macs)

    @classmethod
    def unwhitelist_macs(cls, macs):
        cls.MACS_DISCOVERY.difference_update(macs)

    @classmethod
    def update_filters(cls, ironic):
        macs_active = set(p.address for p in ironic.port.list(limit=0))
        to_blacklist = macs_active - cls.MACS_DISCOVERY

        # Operate on temporary chain
        cls._iptables('-N', cls.NEW_CHAIN)
        # - Blacklist active macs, so that nova can boot them
        for mac in to_blacklist:
            cls._iptables('-A', cls.NEW_CHAIN, '-m', 'mac',
                          '--mac-source', mac, '-j', 'DROP')
        # - Whitelist everything else
        cls._iptables('-A', cls.NEW_CHAIN, '-j', 'ACCEPT')

        # Swap chains
        cls._iptables('-I', 'INPUT', '-i', cls.INTERFACE, '-p', 'udp',
                      '--dport', '67', '-j', cls.NEW_CHAIN)
        cls._iptables('-D', 'INPUT', '-i', cls.INTERFACE, '-p', 'udp',
                      '--dport', '67', '-j', cls.CHAIN,
                      ignore=True)  # may be missing on first run
        cls._iptables('-F', cls.CHAIN)
        cls._iptables('-X', cls.CHAIN)
        cls._iptables('-E', cls.NEW_CHAIN, cls.CHAIN)


def discover(uuids):
    """Initiate discovery for given node uuids."""
    ironic = get_client()
    LOG.debug('Validating nodes %s', uuids)
    nodes = []
    patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'}]
    for uuid in uuids:
        try:
            node = ironic.node.get(uuid)
        except exceptions.HTTPClientError:
            LOG.exception('Failed validation of node %s', uuid)
            continue

        ironic.node.update(uuid, patch)

        nodes.append(node)

    LOG.info('Proceeding with discovery on nodes %s', [n.uuid for n in nodes])

    to_exclude = set()
    for node in nodes:
        if not node.driver.endswith('ssh'):
            continue

        LOG.warn('Driver for %s is %s, requires white-listing MAC',
                 node.uuid, node.driver)

        # TODO(dtantsur): pagination
        ports = ironic.node.list_ports(node.uuid, limit=0)
        to_exclude.update(p.address for p in ports)

    if to_exclude:
        Firewall.whitelist_macs(to_exclude)
        Firewall.update_filters(ironic)

    for node in nodes:
        ironic.node.set_power_state(node.uuid, 'on')
