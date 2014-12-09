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
class TestClient(unittest.TestCase):
    def test_client(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_client_full_url(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port/v1/",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_client_default_url(self, mock_post):
        client.discover(['uuid1', 'uuid2'],
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:5050/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )
