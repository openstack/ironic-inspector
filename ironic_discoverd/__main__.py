import logging
import sys

import eventlet
from flask import Flask, request


from ironic_discoverd.discoverd import (CONF, LOG, process, discover,
                                        Firewall, get_client)


eventlet.monkey_patch()

app = Flask(__name__)


@app.route('/v1/continue', methods=['POST'])
def post_continue():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    eventlet.greenthread.spawn_n(process, data)
    return "{}", 202, {"content-type": "application/json"}


@app.route('/v1/discover', methods=['POST'])
def post_discover():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    eventlet.greenthread.spawn_n(discover, data)
    return "{}", 202, {"content-type": "application/json"}


def periodic_update(ironic):
    while True:
        LOG.debug('Running periodic update of filters')
        Firewall.update_filters(ironic)
        eventlet.greenthread.sleep(15)


if len(sys.argv) < 2:
    sys.exit("Usage: %s config-file" % sys.argv[0])

CONF.read(sys.argv[1])
debug = CONF.getboolean('discoverd', 'debug')

logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
ironic = get_client()
Firewall.init()
eventlet.greenthread.spawn_n(periodic_update, ironic)

try:
    app.run(debug=debug, host=CONF.get('discoverd', 'listen_address'),
            port=CONF.getint('discoverd', 'listen_port'))
finally:
    LOG.info('Waiting for background thread to shutdown')
