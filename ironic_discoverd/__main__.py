import logging
import threading
import time

from flask import Flask, request

from ironic_discoverd.discoverd import (LOG, process, start,
                                        Firewall, get_client)


app = Flask(__name__)


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
        LOG.debug('Running periodic update of filters')
        Firewall.update_filters(ironic)
        for _ in range(15):
            if event.is_set():
                return
            time.sleep(1)


logging.basicConfig(level=logging.INFO)
ironic = get_client()
Firewall.init()
event = threading.Event()
threading.Thread(target=periodic_update, args=(event, ironic)).start()
try:
    app.run(debug=True, host='0.0.0.0', port=5050)
finally:
    LOG.info('Waiting for background thread to shutdown')
    event.set()
