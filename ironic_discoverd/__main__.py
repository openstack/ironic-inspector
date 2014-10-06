import logging
import sys
import threading
import time

from flask import Flask, request

from ironic_discoverd.discoverd import (CONF, LOG, process, start,
                                        Firewall, get_client)


app = Flask(__name__)


@app.route('/v1/continue', methods=['POST'])
def post_continue():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    threading.Thread(target=process, args=(data,)).start()
    return "{}", 202, {"content-type": "application/json"}


@app.route('/v1/discover', methods=['POST'])
def post_discover():
    data = request.get_json(force=True)
    LOG.debug("Got JSON %s, going into processing thread", data)
    threading.Thread(target=start, args=(data,)).start()
    return "{}", 202, {"content-type": "application/json"}


def periodic_update(event, ironic):
    while not event.is_set():
        LOG.debug('Running periodic update of filters')
        Firewall.update_filters(ironic)
        for _ in range(15):
            if event.is_set():
                return
            time.sleep(1)


if len(sys.argv) < 2:
    sys.exit("Usage: %s config-file" % sys.argv[0])

CONF.read(sys.argv[1])
debug = CONF.getboolean('discoverd', 'debug')

logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
ironic = get_client()
Firewall.init()
event = threading.Event()
threading.Thread(target=periodic_update, args=(event, ironic)).start()
try:
    app.run(debug=debug, host='0.0.0.0', port=5050)
finally:
    LOG.info('Waiting for background thread to shutdown')
    event.set()
