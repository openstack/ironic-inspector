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
import os
import re
import ssl
import sys

import flask
from oslo_config import cfg
from oslo_log import log
from oslo_utils import uuidutils
import werkzeug

from ironic_inspector import db
from ironic_inspector.common.i18n import _, _LC, _LE, _LI, _LW
from ironic_inspector.common import swift
from ironic_inspector import conf  # noqa
from ironic_inspector import firewall
from ironic_inspector import introspect
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector import process
from ironic_inspector import rules
from ironic_inspector import utils

CONF = cfg.CONF


app = flask.Flask(__name__)
LOG = log.getLogger('ironic_inspector.main')

MINIMUM_API_VERSION = (1, 0)
CURRENT_API_VERSION = (1, 2)
_MIN_VERSION_HEADER = 'X-OpenStack-Ironic-Inspector-API-Minimum-Version'
_MAX_VERSION_HEADER = 'X-OpenStack-Ironic-Inspector-API-Maximum-Version'
_VERSION_HEADER = 'X-OpenStack-Ironic-Inspector-API-Version'


def _format_version(ver):
    return '%d.%d' % ver


_DEFAULT_API_VERSION = _format_version(MINIMUM_API_VERSION)


def error_response(exc, code=500):
    res = flask.jsonify(error={'message': str(exc)})
    res.status_code = code
    LOG.debug('Returning error to client: %s', exc)
    return res


def convert_exceptions(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except utils.Error as exc:
            return error_response(exc, exc.http_code)
        except werkzeug.exceptions.HTTPException as exc:
            return error_response(exc, exc.code or 400)
        except Exception as exc:
            LOG.exception(_LE('Internal server error'))
            msg = _('Internal server error')
            if CONF.debug:
                msg += ' (%s): %s' % (exc.__class__.__name__, exc)
            return error_response(msg)

    return wrapper


@app.before_request
def check_api_version():
    requested = flask.request.headers.get(_VERSION_HEADER,
                                          _DEFAULT_API_VERSION)
    try:
        requested = tuple(int(x) for x in requested.split('.'))
    except (ValueError, TypeError):
        return error_response(_('Malformed API version: expected string '
                                'in form of X.Y'), code=400)

    if requested < MINIMUM_API_VERSION or requested > CURRENT_API_VERSION:
        return error_response(_('Unsupported API version %(requested)s, '
                                'supported range is %(min)s to %(max)s') %
                              {'requested': _format_version(requested),
                               'min': _format_version(MINIMUM_API_VERSION),
                               'max': _format_version(CURRENT_API_VERSION)},
                              code=406)


@app.after_request
def add_version_headers(res):
    res.headers[_MIN_VERSION_HEADER] = '%s.%s' % MINIMUM_API_VERSION
    res.headers[_MAX_VERSION_HEADER] = '%s.%s' % CURRENT_API_VERSION
    return res


def create_link_object(urls):
    links = []
    for url in urls:
        links.append({"rel": "self",
                      "href": os.path.join(flask.request.url_root, url)})
    return links


def generate_resource_data(resources):
    data = []
    for resource in resources:
        item = {}
        item['name'] = str(resource).split('/')[-1]
        item['links'] = create_link_object([str(resource)[1:]])
        data.append(item)
    return data


@app.route('/', methods=['GET'])
@convert_exceptions
def api_root():
    versions = [
        {
            "status": "CURRENT",
            "id": '%s.%s' % CURRENT_API_VERSION,
        },
    ]

    for version in versions:
        version['links'] = create_link_object(
            ["v%s" % version['id'].split('.')[0]])

    return flask.jsonify(versions=versions)


@app.route('/<version>', methods=['GET'])
@convert_exceptions
def version_root(version):
    pat = re.compile("^\/%s\/[^\/]*?$" % version)

    resources = []
    for url in app.url_map.iter_rules():
        if pat.match(str(url)):
            resources.append(url)

    if not resources:
        raise utils.Error(_('Version not found.'), code=404)

    return flask.jsonify(resources=generate_resource_data(resources))


@app.route('/v1/continue', methods=['POST'])
@convert_exceptions
def api_continue():
    data = flask.request.get_json(force=True)
    LOG.debug("/v1/continue got JSON %s", data)

    return flask.jsonify(process.process(data))


# TODO(sambetts) Add API discovery for this endpoint
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
                              new_ipmi_credentials=new_ipmi_credentials,
                              token=flask.request.headers.get('X-Auth-Token'))
        return '', 202
    else:
        node_info = node_cache.get_node(uuid)
        return flask.json.jsonify(finished=bool(node_info.finished_at),
                                  error=node_info.error or None)


@app.route('/v1/introspection/<uuid>/data', methods=['GET'])
@convert_exceptions
def api_introspection_data(uuid):
    utils.check_auth(flask.request)
    if CONF.processing.store_data == 'swift':
        res = swift.get_introspection_data(uuid)
        return res, 200, {'Content-Type': 'application/json'}
    else:
        return error_response(_('Inspector is not configured to store data. '
                                'Set the [processing] store_data '
                                'configuration option to change this.'),
                              code=404)


def rule_repr(rule, short):
    result = rule.as_dict(short=short)
    result['links'] = [{
        'href': flask.url_for('api_rule', uuid=result['uuid']),
        'rel': 'self'
    }]
    return result


@app.route('/v1/rules', methods=['GET', 'POST', 'DELETE'])
@convert_exceptions
def api_rules():
    utils.check_auth(flask.request)

    if flask.request.method == 'GET':
        res = [rule_repr(rule, short=True) for rule in rules.get_all()]
        return flask.jsonify(rules=res)
    elif flask.request.method == 'DELETE':
        rules.delete_all()
        return '', 204
    else:
        body = flask.request.get_json(force=True)
        if body.get('uuid') and not uuidutils.is_uuid_like(body['uuid']):
            raise utils.Error(_('Invalid UUID value'), code=400)

        rule = rules.create(conditions_json=body.get('conditions', []),
                            actions_json=body.get('actions', []),
                            uuid=body.get('uuid'),
                            description=body.get('description'))
        return flask.jsonify(rule_repr(rule, short=False))


@app.route('/v1/rules/<uuid>', methods=['GET', 'DELETE'])
@convert_exceptions
def api_rule(uuid):
    utils.check_auth(flask.request)

    if flask.request.method == 'GET':
        rule = rules.get(uuid)
        return flask.jsonify(rule_repr(rule, short=False))
    else:
        rules.delete(uuid)
        return '', 204


@app.errorhandler(404)
def handle_404(error):
    return error_response(error, code=404)


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
            sync_with_ironic()
        except Exception:
            LOG.exception(_LE('Periodic clean up of node cache failed'))
        eventlet.greenthread.sleep(period)


def sync_with_ironic():
    ironic = utils.get_client()
    # TODO(yuikotakada): pagination
    ironic_nodes = ironic.node.list(limit=0)
    ironic_node_uuids = {node.uuid for node in ironic_nodes}
    node_cache.delete_nodes_not_in_list(ironic_node_uuids)


def init():
    if utils.get_auth_strategy() != 'noauth':
        utils.add_auth_middleware(app)
    else:
        LOG.warning(_LW('Starting unauthenticated, please check'
                        ' configuration'))

    if CONF.processing.store_data == 'none':
        LOG.warning(_LW('Introspection data will not be stored. Change '
                        '"[processing] store_data" option if this is not the '
                        'desired behavior'))
    elif CONF.processing.store_data == 'swift':
        LOG.info(_LI('Introspection data will be stored in Swift in the '
                     'container %s'), CONF.swift.container)

    db.init()

    try:
        hooks = [ext.name for ext in plugins_base.processing_hooks_manager()]
    except KeyError as exc:
        # stevedore raises KeyError on missing hook
        LOG.critical(_LC('Hook %s failed to load or was not found'), str(exc))
        sys.exit(1)

    LOG.info(_LI('Enabled processing hooks: %s'), hooks)

    if CONF.firewall.manage_firewall:
        firewall.init()
        period = CONF.firewall.firewall_update_period
        utils.spawn_n(periodic_update, period)

    if CONF.timeout > 0:
        period = CONF.clean_up_period
        utils.spawn_n(periodic_clean_up, period)
    else:
        LOG.warning(_LW('Timeout is disabled in configuration'))


def create_ssl_context():
    if not CONF.use_ssl:
        return

    MIN_VERSION = (2, 7, 9)

    if sys.version_info < MIN_VERSION:
        LOG.warning(_LW('Unable to use SSL in this version of Python: '
                        '%{current}, please ensure your version of Python is '
                        'greater than %{min} to enable this feature.'),
                    {'current': '.'.join(map(str, sys.version_info[:3])),
                     'min': '.'.join(map(str, MIN_VERSION))})
        return

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    if CONF.ssl_cert_path and CONF.ssl_key_path:
        try:
            context.load_cert_chain(CONF.ssl_cert_path, CONF.ssl_key_path)
        except IOError as exc:
            LOG.warning(_LW('Failed to load certificate or key from defined '
                            'locations: %{cert} and %{key}, will continue to '
                            'run with the default settings: %{exc}'),
                        {'cert': CONF.ssl_cert_path, 'key': CONF.ssl_key_path,
                         'exc': exc})
        except ssl.SSLError as exc:
            LOG.warning(_LW('There was a problem with the loaded certificate '
                            'and key, will continue to run with the default '
                            'settings: %s'), exc)
    return context


def main(args=sys.argv[1:], in_functional_test=False):  # pragma: no cover
    log.register_options(CONF)
    CONF(args, project='ironic-inspector')
    debug = CONF.debug

    log.set_defaults(default_log_levels=[
        'urllib3.connectionpool=WARN',
        'keystonemiddleware.auth_token=WARN',
        'requests.packages.urllib3.connectionpool=WARN',
        ('ironicclient.common.http=INFO' if debug else
         'ironicclient.common.http=ERROR')])
    log.setup(CONF, 'ironic_inspector')

    app_kwargs = {'debug': debug and not in_functional_test,
                  'host': CONF.listen_address,
                  'port': CONF.listen_port}

    context = create_ssl_context()
    if context:
        app_kwargs['ssl_context'] = context

    init()
    try:
        app.run(**app_kwargs)
    finally:
        firewall.clean_up()
