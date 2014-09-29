import logging
import os
import threading

from flask import Flask, request
from ironicclient import client


app = Flask(__name__)
log = logging.getLogger("discoverd")
os_args = dict((k.lower(), v)
               for (k, v) in os.environ.items()
               if k.startswith('OS_'))


def process(data):
    ironic = client.get_client(1, **os_args)


@app.route('/', methods=['POST'])
def post():
    data = request.get_json(force=True)
    log.debug("Got JSON %s, going into processing thread", data)
    threading.Thread(target=process, args=(data,)).start()
    return "{}", 202, {"content-type": "application/json"}


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    client.get_client(1, **os_args)
    app.run(debug=True, host='0.0.0.0')
