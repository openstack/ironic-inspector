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

import json
import logging
import sys

from flask import Flask, request, json as flask_json  # noqa

from keystoneclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import discover
from ironic_discoverd import firewall
from ironic_discoverd import node_cache
from ironic_discoverd import process
from ironic_discoverd import utils


app = Flask(__name__)
LOG = logging.getLogger('ironic_discoverd.main')


@app.route('/v1/continue', methods=['POST'])
def post_continue():
    data = request.get_json(force=True)
    LOG.debug("/v1/continue got JSON %s", data)
    try:
        res = process.process(data)
    except utils.DiscoveryFailed as exc:
        LOG.debug('/v1/continue failed: %s', exc)
        return str(exc), exc.http_code
    else:
        return json.dumps(res), 200, {'Content-Type': 'applications/json'}


@app.route('/v1/introspection/<uuid>')
def introspection(uuid):
    # NOTE(dtantsur): in the future this method will also accept PUT
    # to initiate introspection.
    node_info = node_cache.get_node(uuid)
    return flask_json.jsonify(finished=bool(node_info.finished_at),
                              error=node_info.error or None)


@app.route('/v1/discover', methods=['POST'])
def post_discover():
    if conf.getboolean('discoverd', 'authenticate'):
        if not request.headers.get('X-Auth-Token'):
            LOG.error("No X-Auth-Token header, rejecting request")
            return 'Authentication required', 401
        try:
            utils.get_keystone(token=request.headers['X-Auth-Token'])
        except exceptions.Unauthorized:
            LOG.error("Keystone denied access, rejecting request")
            return 'Access denied', 403
        # TODO(dtanstur): check for admin role

    data = request.get_json(force=True)
    LOG.debug("/v1/discover got JSON %s", data)
    try:
        discover.discover(data)
    except utils.DiscoveryFailed as exc:
        LOG.debug('/v1/discover failed: %s', exc)
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


def periodic_clean_up(period):
    while True:
        LOG.debug('Running periodic clean up of timed out nodes')
        try:
            if node_cache.clean_up():
                firewall.update_filters()
        except Exception:
            LOG.exception('Periodic clean up failed')
        eventlet.greenthread.sleep(period)


def check_ironic_available():
    """Try to make sure we can reach Ironic.

    Ensure that:
    1. Keystone access is configured properly
    2. Keystone has already started
    3. Ironic has already started
    """
    attempts = conf.getint('discoverd', 'ironic_retry_attempts')
    assert attempts >= 0
    retry_period = conf.getint('discoverd', 'ironic_retry_period')
    LOG.debug('Trying to connect to Ironic')
    for i in range(attempts + 1):  # one attempt always required
        try:
            utils.get_client().driver.list()
        except Exception as exc:
            if i == attempts:
                raise
            LOG.warning('Unable to connect to Ironic or Keystone, retrying %d '
                        'times more: %s', attempts - i, exc)
        else:
            break
        eventlet.greenthread.sleep(retry_period)


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: %s config-file" % sys.argv[0])

    conf.read(sys.argv[1])
    debug = conf.getboolean('discoverd', 'debug')

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(
        logging.WARNING)
    logging.getLogger('ironicclient.common.http').setLevel(
        logging.INFO if debug else logging.ERROR)

    if not conf.getboolean('discoverd', 'authenticate'):
        LOG.warning('Starting unauthenticated, please check configuration')

    node_cache.init()
    check_ironic_available()

    if conf.getboolean('discoverd', 'manage_firewall'):
        firewall.init()
        period = conf.getint('discoverd', 'firewall_update_period')
        eventlet.greenthread.spawn_n(periodic_update, period)

    if conf.getint('discoverd', 'timeout') > 0:
        period = conf.getint('discoverd', 'clean_up_period')
        eventlet.greenthread.spawn_n(periodic_clean_up, period)
    else:
        LOG.warning('Timeout is disabled in configuration')

    app.run(debug=debug,
            host=conf.get('discoverd', 'listen_address'),
            port=conf.getint('discoverd', 'listen_port'))
