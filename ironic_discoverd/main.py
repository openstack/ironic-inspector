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
eventlet.monkey_patch()

import functools
import json
import logging
import sys

import flask
from oslo_config import cfg
from oslo_utils import uuidutils

from ironic_discoverd.common.i18n import _, _LE, _LW
# Import configuration options
from ironic_discoverd import conf  # noqa
from ironic_discoverd import firewall
from ironic_discoverd import introspect
from ironic_discoverd import node_cache
from ironic_discoverd import process
from ironic_discoverd import utils

CONF = cfg.CONF


app = flask.Flask(__name__)
LOG = logging.getLogger('ironic_discoverd.main')


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
    utils.check_auth(flask.request)

    if not uuidutils.is_uuid_like(uuid):
        raise utils.Error(_('Invalid UUID value'), code=400)

    if flask.request.method == 'POST':
        new_ipmi_password = flask.request.args.get('new_ipmi_password',
                                                   type=str,
                                                   default=None)
        if new_ipmi_password:
            new_ipmi_username = flask.request.args.get('new_ipmi_username',
                                                       type=str,
                                                       default=None)
            new_ipmi_credentials = (new_ipmi_username, new_ipmi_password)
        else:
            new_ipmi_credentials = None

        introspect.introspect(uuid,
                              new_ipmi_credentials=new_ipmi_credentials)
        return '', 202
    else:
        node_info = node_cache.get_node(uuid)
        return flask.json.jsonify(finished=bool(node_info.finished_at),
                                  error=node_info.error or None)


@app.route('/v1/discover', methods=['POST'])
@convert_exceptions
def api_discover():
    utils.check_auth(flask.request)

    data = flask.request.get_json(force=True)
    LOG.debug("/v1/discover got JSON %s", data)

    for uuid in data:
        if not uuidutils.is_uuid_like(uuid):
            raise utils.Error(_('Invalid UUID value'), code=400)

    for uuid in data:
        introspect.introspect(uuid)
    return "", 202


def periodic_update(period):  # pragma: no cover
    while True:
        LOG.debug('Running periodic update of filters')
        try:
            firewall.update_filters()
        except Exception:
            LOG.exception(_LE('Periodic update failed'))
        eventlet.greenthread.sleep(period)


def periodic_clean_up(period):  # pragma: no cover
    while True:
        LOG.debug('Running periodic clean up of node cache')
        try:
            if node_cache.clean_up():
                firewall.update_filters()
        except Exception:
            LOG.exception(_LE('Periodic clean up of node cache failed'))
        eventlet.greenthread.sleep(period)


def check_ironic_available():
    """Try to make sure we can reach Ironic.

    Ensure that:
    1. Keystone access is configured properly
    2. Keystone has already started
    3. Ironic has already started
    """
    attempts = CONF.discoverd.ironic_retry_attempts
    assert attempts >= 0
    retry_period = CONF.discoverd.ironic_retry_period
    LOG.debug('Trying to connect to Ironic')
    for i in range(attempts + 1):  # one attempt always required
        try:
            utils.get_client().driver.list()
        except Exception as exc:
            if i == attempts:
                raise
            LOG.warning(_LW('Unable to connect to Ironic or Keystone, retrying'
                            ' %(count)d times more: %(exc)s') %
                        {'count': attempts - i, 'exc': exc})
        else:
            break
        eventlet.greenthread.sleep(retry_period)


def init():
    if CONF.discoverd.authenticate:
        utils.add_auth_middleware(app)
    else:
        LOG.warning(_LW('Starting unauthenticated, please check'
                        ' configuration'))

    node_cache.init()
    check_ironic_available()

    if CONF.discoverd.manage_firewall:
        firewall.init()
        period = CONF.discoverd.firewall_update_period
        eventlet.greenthread.spawn_n(periodic_update, period)

    if CONF.discoverd.timeout > 0:
        period = CONF.discoverd.clean_up_period
        eventlet.greenthread.spawn_n(periodic_clean_up, period)
    else:
        LOG.warning(_LW('Timeout is disabled in configuration'))


def main(args=sys.argv[1:]):  # pragma: no cover
    CONF(args, project='ironic-discoverd')
    debug = CONF.discoverd.debug

    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    for third_party in ('urllib3.connectionpool',
                        'keystonemiddleware.auth_token',
                        'requests.packages.urllib3.connectionpool'):
        logging.getLogger(third_party).setLevel(logging.WARNING)
    logging.getLogger('ironicclient.common.http').setLevel(
        logging.INFO if debug else logging.ERROR)

    init()
    app.run(debug=debug,
            host=CONF.discoverd.listen_address,
            port=CONF.discoverd.listen_port)
