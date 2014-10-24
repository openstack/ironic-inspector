import eventlet
eventlet.monkey_patch(thread=False)

import logging
import sys

from flask import Flask, request

from keystoneclient import exceptions

from ironic_discoverd import discoverd
from ironic_discoverd import firewall


app = Flask(__name__)
LOG = discoverd.LOG


@app.route('/v1/continue', methods=['POST'])
def post_continue():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    eventlet.greenthread.spawn_n(discoverd.process, data)
    return "{}", 202, {"content-type": "application/json"}


@app.route('/v1/discover', methods=['POST'])
def post_discover():
    if discoverd.CONF.getboolean('discoverd', 'authenticate'):
        if not request.headers.get('X-Auth-Token'):
            LOG.debug("No X-Auth-Token header, rejecting")
            return 'Authentication required', 401
        try:
            discoverd.get_keystone(token=request.headers['X-Auth-Token'])
        except exceptions.Unauthorized:
            LOG.debug("Keystone denied access, rejecting")
            return 'Access denied', 403
        # TODO(dtanstur): check for admin role

    data = request.get_json(force=True)
    LOG.debug("Got JSON %s", data)
    try:
        discoverd.discover(data)
    except discoverd.DiscoveryFailed as exc:
        return str(exc), exc.http_code
    else:
        return "", 202


def periodic_update(period):
    while True:
        LOG.debug('Running periodic update of filters')
        try:
            firewall.update_filters(discoverd.get_client())
        except Exception:
            LOG.exception('Periodic update failed')
        eventlet.greenthread.sleep(period)


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: %s config-file" % sys.argv[0])

    discoverd.CONF.read(sys.argv[1])
    debug = discoverd.CONF.getboolean('discoverd', 'debug')

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
    logging.getLogger('requests.packages.urllib3.connectionpool') \
        .setLevel(logging.WARNING)

    if not discoverd.CONF.getboolean('discoverd', 'authenticate'):
        LOG.warning('Starting unauthenticated, please check configuration')

    interface = discoverd.CONF.get('discoverd', 'dnsmasq_interface')
    firewall.init(interface)

    # Before proceeding we try to make sure:
    # 1. Keystone access is configured properly
    # 2. Keystone has already started
    # 3. Ironic has already started
    attempts = discoverd.CONF.getint('discoverd', 'ironic_retry_attempts')
    assert attempts >= 0
    retry_period = discoverd.CONF.getint('discoverd', 'ironic_retry_period')
    LOG.debug('Trying to connect to Ironic')
    for i in range(attempts + 1):  # one attempt always required
        try:
            discoverd.get_client().driver.list()
        except Exception as exc:
            if i == attempts:
                raise
            LOG.error('Unable to connect to Ironic or Keystone, retrying %d '
                      'times more: %s', attempts - i, exc)
        else:
            break
        eventlet.greenthread.sleep(retry_period)

    period = discoverd.CONF.getint('discoverd', 'firewall_update_period')
    eventlet.greenthread.spawn_n(periodic_update, period)

    app.run(debug=debug,
            host=discoverd.CONF.get('discoverd', 'listen_address'),
            port=discoverd.CONF.getint('discoverd', 'listen_port'))
