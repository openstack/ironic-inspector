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

import functools
import os
import re

import flask
from oslo_config import cfg
from oslo_utils import uuidutils
import werkzeug

from ironic_inspector import api_tools
from ironic_inspector.common.i18n import _
from ironic_inspector.common import ironic as ir_utils
from ironic_inspector.common import swift
from ironic_inspector import conf  # noqa
from ironic_inspector import introspect
from ironic_inspector import node_cache
from ironic_inspector import process
from ironic_inspector import rules
from ironic_inspector import utils

CONF = cfg.CONF


app = flask.Flask(__name__)
LOG = utils.getProcessingLogger(__name__)

MINIMUM_API_VERSION = (1, 0)
CURRENT_API_VERSION = (1, 12)
DEFAULT_API_VERSION = CURRENT_API_VERSION
_LOGGING_EXCLUDED_KEYS = ('logs',)


def _get_version():
    ver = flask.request.headers.get(conf.VERSION_HEADER,
                                    _DEFAULT_API_VERSION)
    try:
        requested = tuple(int(x) for x in ver.split('.'))
    except (ValueError, TypeError):
        return error_response(_('Malformed API version: expected string '
                                'in form of X.Y'), code=400)
    return requested


def _format_version(ver):
    return '%d.%d' % ver


_DEFAULT_API_VERSION = _format_version(DEFAULT_API_VERSION)


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
            LOG.exception('Internal server error')
            msg = _('Internal server error')
            if CONF.debug:
                msg += ' (%s): %s' % (exc.__class__.__name__, exc)
            return error_response(msg)

    return wrapper


@app.before_request
def check_api_version():
    requested = _get_version()

    if requested < MINIMUM_API_VERSION or requested > CURRENT_API_VERSION:
        return error_response(_('Unsupported API version %(requested)s, '
                                'supported range is %(min)s to %(max)s') %
                              {'requested': _format_version(requested),
                               'min': _format_version(MINIMUM_API_VERSION),
                               'max': _format_version(CURRENT_API_VERSION)},
                              code=406)


@app.after_request
def add_version_headers(res):
    res.headers[conf.MIN_VERSION_HEADER] = '%s.%s' % MINIMUM_API_VERSION
    res.headers[conf.MAX_VERSION_HEADER] = '%s.%s' % CURRENT_API_VERSION
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


def generate_introspection_status(node):
    """Return a dict representing current node status.

    :param node: a NodeInfo instance
    :return: dictionary
    """
    started_at = node.started_at.isoformat()
    finished_at = node.finished_at.isoformat() if node.finished_at else None

    status = {}
    status['uuid'] = node.uuid
    status['finished'] = bool(node.finished_at)
    status['state'] = node.state
    status['started_at'] = started_at
    status['finished_at'] = finished_at
    status['error'] = node.error
    status['links'] = create_link_object(
        ["v%s/introspection/%s" % (CURRENT_API_VERSION[0], node.uuid)])
    return status


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
    if not isinstance(data, dict):
        raise utils.Error(_('Invalid data: expected a JSON object, got %s') %
                          data.__class__.__name__)

    logged_data = {k: (v if k not in _LOGGING_EXCLUDED_KEYS else '<hidden>')
                   for k, v in data.items()}
    LOG.debug("Received data from the ramdisk: %s", logged_data,
              data=data)

    return flask.jsonify(process.process(data))


# TODO(sambetts) Add API discovery for this endpoint
@app.route('/v1/introspection/<node_id>', methods=['GET', 'POST'])
@convert_exceptions
def api_introspection(node_id):
    utils.check_auth(flask.request)

    if flask.request.method == 'POST':
        introspect.introspect(node_id,
                              token=flask.request.headers.get('X-Auth-Token'))
        return '', 202
    else:
        node_info = node_cache.get_node(node_id)
        return flask.json.jsonify(generate_introspection_status(node_info))


@app.route('/v1/introspection', methods=['GET'])
@convert_exceptions
def api_introspection_statuses():
    utils.check_auth(flask.request)

    nodes = node_cache.get_node_list(
        marker=api_tools.marker_field(),
        limit=api_tools.limit_field(default=CONF.api_max_limit)
    )
    data = {
        'introspection': [generate_introspection_status(node)
                          for node in nodes]
    }
    return flask.json.jsonify(data)


@app.route('/v1/introspection/<node_id>/abort', methods=['POST'])
@convert_exceptions
def api_introspection_abort(node_id):
    utils.check_auth(flask.request)
    introspect.abort(node_id, token=flask.request.headers.get('X-Auth-Token'))
    return '', 202


@app.route('/v1/introspection/<node_id>/data', methods=['GET'])
@convert_exceptions
def api_introspection_data(node_id):
    utils.check_auth(flask.request)

    if CONF.processing.store_data == 'swift':
        if not uuidutils.is_uuid_like(node_id):
            node = ir_utils.get_node(node_id, fields=['uuid'])
            node_id = node.uuid
        res = swift.get_introspection_data(node_id)
        return res, 200, {'Content-Type': 'application/json'}
    else:
        return error_response(_('Inspector is not configured to store data. '
                                'Set the [processing] store_data '
                                'configuration option to change this.'),
                              code=404)


@app.route('/v1/introspection/<node_id>/data/unprocessed', methods=['POST'])
@convert_exceptions
def api_introspection_reapply(node_id):
    utils.check_auth(flask.request)

    if flask.request.content_length:
        return error_response(_('User data processing is not '
                                'supported yet'), code=400)

    if CONF.processing.store_data == 'swift':
        process.reapply(node_id)
        return '', 202
    else:
        return error_response(_('Inspector is not configured to store'
                                ' data. Set the [processing] '
                                'store_data configuration option to '
                                'change this.'), code=400)


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

        response_code = (200 if _get_version() < (1, 6) else 201)
        return flask.make_response(
            flask.jsonify(rule_repr(rule, short=False)), response_code)


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
