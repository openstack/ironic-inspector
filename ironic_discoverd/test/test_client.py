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
from oslo_utils import netutils
from oslo_utils import uuidutils

from ironic_discoverd import client


@mock.patch.object(client.requests, 'post', autospec=True,
                   **{'return_value.status_code': 200})
class TestIntrospect(unittest.TestCase):
    def setUp(self):
        super(TestIntrospect, self).setUp()
        self.uuid = uuidutils.generate_uuid()
        self.my_ip = 'http://' + netutils.get_my_ipv4() + ':5050/v1'

    def test(self, mock_post):
        client.introspect(self.uuid, base_url="http://host:port",
                          auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/introspection/%s" % self.uuid,
            headers={'X-Auth-Token': 'token'},
            params={'new_ipmi_username': None, 'new_ipmi_password': None}
        )

    def test_invalid_input(self, _):
        self.assertRaises(TypeError, client.introspect, 42)
        self.assertRaises(ValueError, client.introspect, 'uuid',
                          new_ipmi_username='user')

    def test_full_url(self, mock_post):
        client.introspect(self.uuid, base_url="http://host:port/v1/",
                          auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/introspection/%s" % self.uuid,
            headers={'X-Auth-Token': 'token'},
            params={'new_ipmi_username': None, 'new_ipmi_password': None}
        )

    def test_default_url(self, mock_post):
        client.introspect(self.uuid, auth_token="token")
        mock_post.assert_called_once_with(
            "%(my_ip)s/introspection/%(uuid)s" %
            {'my_ip': self.my_ip, 'uuid': self.uuid},
            headers={'X-Auth-Token': 'token'},
            params={'new_ipmi_username': None, 'new_ipmi_password': None}
        )

    def test_set_ipmi_credentials(self, mock_post):
        client.introspect(self.uuid, base_url="http://host:port",
                          auth_token="token", new_ipmi_password='p',
                          new_ipmi_username='u')
        mock_post.assert_called_once_with(
            "http://host:port/v1/introspection/%s" % self.uuid,
            headers={'X-Auth-Token': 'token'},
            params={'new_ipmi_username': 'u', 'new_ipmi_password': 'p'}
        )

    def test_none_ok(self, mock_post):
        client.introspect(self.uuid)
        mock_post.assert_called_once_with(
            "%(my_ip)s/introspection/%(uuid)s" %
            {'my_ip': self.my_ip, 'uuid': self.uuid},
            headers={},
            params={'new_ipmi_username': None, 'new_ipmi_password': None}
        )

    def test_failed(self, mock_post):
        mock_post.return_value.status_code = 404
        mock_post.return_value.content = b"boom"
        self.assertRaisesRegexp(client.ClientError, "boom",
                                client.introspect, self.uuid)


@mock.patch.object(client.requests, 'post', autospec=True,
                   **{'return_value.status_code': 200})
class TestDiscover(unittest.TestCase):
    def setUp(self):
        super(TestDiscover, self).setUp()
        self.uuid = uuidutils.generate_uuid()

    def test_old_discover(self, mock_post):
        uuid2 = uuidutils.generate_uuid()
        client.discover([self.uuid, uuid2], base_url="http://host:port",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["%(uuid1)s", "%(uuid2)s"]' % {'uuid1': self.uuid,
                                                 'uuid2': uuid2},
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_invalid_input(self, _):
        self.assertRaises(TypeError, client.discover, 42)
        self.assertRaises(TypeError, client.discover, [42])

    def test_failed(self, mock_post):
        mock_post.return_value.status_code = 404
        mock_post.return_value.content = b"boom"
        self.assertRaisesRegexp(client.ClientError, "boom",
                                client.discover, [self.uuid])


@mock.patch.object(client.requests, 'get', autospec=True,
                   **{'return_value.status_code': 200})
class TestGetStatus(unittest.TestCase):
    def setUp(self):
        super(TestGetStatus, self).setUp()
        self.uuid = uuidutils.generate_uuid()
        self.my_ip = 'http://' + netutils.get_my_ipv4() + ':5050/v1'

    def test(self, mock_get):
        mock_get.return_value.json.return_value = 'json'

        client.get_status(self.uuid, auth_token='token')

        mock_get.assert_called_once_with(
            "%(my_ip)s/introspection/%(uuid)s" %
            {'my_ip': self.my_ip, 'uuid': self.uuid},
            headers={'X-Auth-Token': 'token'}
        )

    def test_invalid_input(self, _):
        self.assertRaises(TypeError, client.get_status, 42)

    def test_failed(self, mock_post):
        mock_post.return_value.status_code = 404
        mock_post.return_value.content = b"boom"
        self.assertRaisesRegexp(client.ClientError, "boom",
                                client.get_status, self.uuid)
