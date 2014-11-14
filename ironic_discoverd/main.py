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

import eventlet
eventlet.monkey_patch(thread=False)

import logging
import sys

from flask import Flask, request  # noqa

from keystoneclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import discoverd
from ironic_discoverd import firewall
from ironic_discoverd import utils


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
    if conf.getboolean('discoverd', 'authenticate'):
        if not request.headers.get('X-Auth-Token'):
            LOG.debug("No X-Auth-Token header, rejecting")
            return 'Authentication required', 401
        try:
            utils.get_keystone(token=request.headers['X-Auth-Token'])
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
            firewall.update_filters()
        except Exception:
            LOG.exception('Periodic update failed')
        eventlet.greenthread.sleep(period)


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: %s config-file" % sys.argv[0])

    conf.read(sys.argv[1])
    debug = conf.getboolean('discoverd', 'debug')

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(
        logging.WARNING)

    if not conf.getboolean('discoverd', 'authenticate'):
        LOG.warning('Starting unauthenticated, please check configuration')

    firewall.init()
    utils.check_ironic_available()

    period = conf.getint('discoverd', 'firewall_update_period')
    eventlet.greenthread.spawn_n(periodic_update, period)

    app.run(debug=debug,
            host=conf.get('discoverd', 'listen_address'),
            port=conf.getint('discoverd', 'listen_port'))
