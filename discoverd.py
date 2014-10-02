import logging
import os
import re
import threading
import time

from flask import Flask, request
from ironicclient import client, exceptions


app = Flask(__name__)

LOG = logging.getLogger("discoverd")
OS_ARGS = dict((k.lower(), v)
               for (k, v) in os.environ.items()
               if k.startswith('OS_'))
ALLOW_SEARCH_BY_MAC = True


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

    ironic = client.get_client(1, **OS_ARGS)
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

    if not node.maintenance:
        LOG.error('Refusing to apply discovered data to node %s '
                  'which is not in maintenance state', node.uuid)
        return

    patch = [{'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'}]
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
                        'database for another node - skipping',
                        {'mac': mac, 'node': node.uuid})

    LOG.info('Node %s was updated with data from discovery process, forcing '
             'power off', node.uuid)

    ironic.node.set_power_state(node.uuid, 'off')


LOCK = threading.RLock()
MACS_DISCOVERY = set()


def update_filters(ironic):
    """Update firewall rules for TFTP server."""
    with LOCK:
        macs_active = set(p.address for p in ironic.port.list(limit=0))
        to_blacklist = macs_active - MACS_DISCOVERY
        # TODO(dtantsur): change iptables configuration


def start(uuids):
    """Initiate discovery for given node uuids."""
    ironic = client.get_client(1, **OS_ARGS)
    LOG.debug('Validating nodes %s', uuids)
    nodes = []
    for uuid in uuids:
        try:
            node = ironic.node.get(uuid)
        except exceptions.HTTPClientError:
            LOG.exception('Failed validation of node %s', uuid)
            continue

        if not node.maintenance:
            LOG.error('Node %s not in maintenance - skipping', uuid)
            continue

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
        MACS_DISCOVERY.update(to_exclude)
        update_filters(ironic)

    for node in nodes:
        ironic.node.set_power_state(node.uuid, 'on')


@app.route('/continue', methods=['POST'])
def post_continue():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    threading.Thread(target=process, args=(data,)).start()
    return "{}", 202, {"content-type": "application/json"}


@app.route('/start', methods=['POST'])
def post_start():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    threading.Thread(target=start, args=(data,)).start()
    return "{}", 202, {"content-type": "application/json"}


def periodic_update(event, ironic):
    while not event.is_set():
        LOG.info('Running periodic update of filters')
        update_filters(ironic)
        time.sleep(30)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    ironic = client.get_client(1, **OS_ARGS)
    event = threading.Event()
    threading.Thread(target=periodic_update, args=(event, ironic)).start()
    try:
        app.run(debug=True, host='0.0.0.0', port=5050)
    finally:
        LOG.info('Waiting for background thread to shutdown')
        event.set()
