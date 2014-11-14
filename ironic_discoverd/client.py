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

import argparse
import json

import requests
import six


_DEFAULT_URL = 'http://127.0.0.1:5050/v1'


def discover(uuids, base_url=_DEFAULT_URL, auth_token=''):
    """Post node UUID's for discovery.

    :param uuids: list of UUID's.
    :param base_url: *ironic-discoverd* URL in form: http://host:port[/ver],
                     defaults to ``http://127.0.0.1:5050/v1``.
    :param auth_token: Keystone authentication token.
    :raises: *requests* library HTTP errors.
    """
    if not all(isinstance(s, six.string_types) for s in uuids):
        raise TypeError("Expected list of strings for uuids argument, got %s" %
                        uuids)

    base_url = base_url.rstrip('/')
    if not base_url.endswith('v1'):
        base_url += '/v1'

    headers = {'Content-Type': 'application/json',
               'X-Auth-Token': auth_token}
    res = requests.post(base_url + "/discover",
                        data=json.dumps(uuids), headers=headers)
    res.raise_for_status()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Discover nodes.')
    parser.add_argument('uuids', metavar='UUID', type=str, nargs='+',
                        help='node UUID\'s.')
    parser.add_argument('--base-url', dest='base_url', action='store',
                        default=_DEFAULT_URL,
                        help='base URL, default to localhost.')
    parser.add_argument('--auth-token', dest='auth_token', action='store',
                        default='',
                        help='Keystone token.')
    args = parser.parse_args()
    discover(args.uuids, base_url=args.base_url, auth_token=args.auth_token)
