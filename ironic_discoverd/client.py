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

from __future__ import print_function

import argparse
import json

import requests
import six


_DEFAULT_URL = 'http://127.0.0.1:5050/v1'


def _prepare(base_url, auth_token):
    base_url = base_url.rstrip('/')
    if not base_url.endswith('v1'):
        base_url += '/v1'
    headers = {'X-Auth-Token': auth_token}
    return base_url, headers


def introspect(uuid, base_url=_DEFAULT_URL, auth_token=''):
    """Start introspection for a node.

    :param uuid: node uuid
    :param base_url: *ironic-discoverd* URL in form: http://host:port[/ver],
                     defaults to ``http://127.0.0.1:5050/v1``.
    :param auth_token: Keystone authentication token.
    """
    if not isinstance(uuid, six.string_types):
        raise TypeError("Expected string for uuid argument, got %r" % uuid)

    base_url, headers = _prepare(base_url, auth_token)
    res = requests.post("%s/introspection/%s" % (base_url, uuid),
                        headers=headers)
    res.raise_for_status()


def get_status(uuid, base_url=_DEFAULT_URL, auth_token=''):
    """Get introspection status for a node.

    New in ironic-discoverd version 1.0.0.
    :param uuid: node uuid.
    :param base_url: *ironic-discoverd* URL in form: http://host:port[/ver],
                     defaults to ``http://127.0.0.1:5050/v1``.
    :param auth_token: Keystone authentication token.
    :raises: *requests* library HTTP errors.
    """
    if not isinstance(uuid, six.string_types):
        raise TypeError("Expected string for uuid argument, got %r" % uuid)

    base_url, headers = _prepare(base_url, auth_token)
    res = requests.get("%s/introspection/%s" % (base_url, uuid),
                       headers=headers)
    res.raise_for_status()
    return res.json()


def discover(uuids, base_url=_DEFAULT_URL, auth_token=''):
    """Post node UUID's for discovery.

    DEPRECATED. Use introspect instead.
    """
    if not all(isinstance(s, six.string_types) for s in uuids):
        raise TypeError("Expected list of strings for uuids argument, got %s" %
                        uuids)

    base_url, headers = _prepare(base_url, auth_token)
    headers['Content-Type'] = 'application/json'
    res = requests.post(base_url + "/discover",
                        data=json.dumps(uuids), headers=headers)
    res.raise_for_status()


if __name__ == '__main__':  # pragma: no cover
    parser = argparse.ArgumentParser(description='Discover nodes.')
    parser.add_argument('cmd', metavar='cmd',
                        choices=['introspect', 'get_status'],
                        help='command: introspect or get_status.')
    parser.add_argument('uuid', metavar='UUID', type=str,
                        help='node UUID.')
    parser.add_argument('--base-url', dest='base_url', action='store',
                        default=_DEFAULT_URL,
                        help='base URL, default to localhost.')
    parser.add_argument('--auth-token', dest='auth_token', action='store',
                        default='',
                        help='Keystone token.')
    args = parser.parse_args()
    func = globals()[args.cmd]
    try:
        res = func(uuid=args.uuid, base_url=args.base_url,
                   auth_token=args.auth_token)
    except Exception as exc:
        print('Error:', exc)
    else:
        if res:
            print(json.dumps(res))
