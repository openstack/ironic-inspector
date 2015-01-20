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

import unittest

import mock

from ironic_discoverd import client


@mock.patch.object(client.requests, 'post', autospec=True)
class TestIntrospect(unittest.TestCase):
    def test(self, mock_post):
        client.introspect('uuid1', base_url="http://host:port",
                          auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/introspection/uuid1",
            headers={'X-Auth-Token': 'token'}
        )

    def test_invalid_input(self, _):
        self.assertRaises(TypeError, client.introspect, 42)

    def test_full_url(self, mock_post):
        client.introspect('uuid1', base_url="http://host:port/v1/",
                          auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/introspection/uuid1",
            headers={'X-Auth-Token': 'token'}
        )

    def test_default_url(self, mock_post):
        client.introspect('uuid1', auth_token="token")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:5050/v1/introspection/uuid1",
            headers={'X-Auth-Token': 'token'}
        )


@mock.patch.object(client.requests, 'post', autospec=True)
class TestDiscover(unittest.TestCase):
    def test_old_discover(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_invalid_input(self, _):
        self.assertRaises(TypeError, client.discover, 42)
        self.assertRaises(TypeError, client.discover, [42])


@mock.patch.object(client.requests, 'get', autospec=True)
class TestGetStatus(unittest.TestCase):
    def test(self, mock_get):
        mock_get.return_value.json.return_value = 'json'

        client.get_status('uuid', auth_token='token')

        mock_get.assert_called_once_with(
            "http://127.0.0.1:5050/v1/introspection/uuid",
            headers={'X-Auth-Token': 'token'}
        )

    def test_invalid_input(self, _):
        self.assertRaises(TypeError, client.get_status, 42)
