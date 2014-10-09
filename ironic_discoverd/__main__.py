import logging
import sys

import eventlet
from flask import Flask, request

from keystoneclient import exceptions

from ironic_discoverd import discoverd


eventlet.monkey_patch()

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
    LOG.debug("Got JSON %s, going into processing thread", data)
    eventlet.greenthread.spawn_n(discoverd.discover, data)
    return "{}", 202, {"content-type": "application/json"}


def periodic_update():
    ironic = discoverd.get_client()
    while True:
        LOG.debug('Running periodic update of filters')
        discoverd.Firewall.update_filters(ironic)
        eventlet.greenthread.sleep(15)


if len(sys.argv) < 2:
    sys.exit("Usage: %s config-file" % sys.argv[0])

discoverd.CONF.read(sys.argv[1])
debug = discoverd.CONF.getboolean('discoverd', 'debug')

logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
discoverd.Firewall.init()
eventlet.greenthread.spawn_n(periodic_update)

app.run(debug=debug, host=discoverd.CONF.get('discoverd', 'listen_address'),
        port=discoverd.CONF.getint('discoverd', 'listen_port'))
