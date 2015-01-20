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

import sys

import eventlet
eventlet.monkey_patch(thread=(sys.version_info < (3, 3)))

import argparse
import functools
import json
import logging
import sys

import flask
from keystoneclient import exceptions

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import introspect
from ironic_discoverd import node_cache
from ironic_discoverd import process
from ironic_discoverd import utils


app = flask.Flask(__name__)
LOG = logging.getLogger('ironic_discoverd.main')


def check_auth():
    """Check whether request is properly authenticated."""
    if not conf.getboolean('discoverd', 'authenticate'):
        return

    if not flask.request.headers.get('X-Auth-Token'):
        LOG.error("No X-Auth-Token header, rejecting request")
        raise utils.Error('Authentication required', code=401)
    try:
        utils.check_is_admin(token=flask.request.headers['X-Auth-Token'])
    except exceptions.Unauthorized as exc:
        LOG.error("Keystone denied access: %s, rejecting request", exc)
        raise utils.Error('Access denied', code=403)


def convert_exceptions(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except utils.Error as exc:
            return str(exc), exc.http_code

    return wrapper


@app.route('/v1/continue', methods=['POST'])
@convert_exceptions
def api_continue():
    data = flask.request.get_json(force=True)
    LOG.debug("/v1/continue got JSON %s", data)

    res = process.process(data)
    return json.dumps(res), 200, {'Content-Type': 'applications/json'}


@app.route('/v1/introspection/<uuid>', methods=['GET', 'POST'])
@convert_exceptions
def api_introspection(uuid):
    check_auth()

    if flask.request.method == 'POST':
        setup_ipmi_credentials = flask.request.args.get(
            'setup_ipmi_credentials',
            type=bool,
            default=False)
        introspect.introspect(uuid,
                              setup_ipmi_credentials=setup_ipmi_credentials)
        return '', 202
    else:
        node_info = node_cache.get_node(uuid)
        return flask.json.jsonify(finished=bool(node_info.finished_at),
                                  error=node_info.error or None)


@app.route('/v1/discover', methods=['POST'])
@convert_exceptions
def api_discover():
    check_auth()
    data = flask.request.get_json(force=True)
    LOG.debug("/v1/discover got JSON %s", data)

    for uuid in data:
        introspect.introspect(uuid)
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
        LOG.debug('Running periodic clean up of node cache')
        try:
            if node_cache.clean_up():
                firewall.update_filters()
        except Exception:
            LOG.exception('Periodic clean up of node cache failed')
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


def config_shim(args):
    """Make new argument parsing method backwards compatible."""
    if len(args) == 2 and args[1][0] != '-':
        return ['--config-file', args[1]]


def main():
    old_args = config_shim(sys.argv)
    parser = argparse.ArgumentParser(description='''Hardware introspection
                                                 service for OpenStack Ironic.
                                                 ''')
    parser.add_argument('--config-file', dest='config', required=True)
    # if parse_args is passed None it uses sys.argv instead.
    args = parser.parse_args(old_args)

    conf.read(args.config)
    debug = conf.getboolean('discoverd', 'debug')

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARNING)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(
        logging.WARNING)
    logging.getLogger('ironicclient.common.http').setLevel(
        logging.INFO if debug else logging.ERROR)

    if old_args:
        LOG.warning('"ironic-discoverd <config-file>" syntax is deprecated use'
                    ' "ironic-discoverd --config-file <config-file>" instead')

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
