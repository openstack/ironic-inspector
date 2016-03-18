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

import mock

from keystoneauth1 import exceptions as kaexc
from keystoneauth1 import loading as kaloading
from oslo_config import cfg

from ironic_inspector.common import keystone
from ironic_inspector.test import base


CONF = cfg.CONF
TESTGROUP = 'keystone_test'


class KeystoneTest(base.BaseTest):

    def setUp(self):
        super(KeystoneTest, self).setUp()
        self.cfg.conf.register_group(cfg.OptGroup(TESTGROUP))

    def test_register_auth_opts(self):
        keystone.register_auth_opts(TESTGROUP)
        auth_opts = ['auth_type', 'auth_section']
        sess_opts = ['certfile', 'keyfile', 'insecure', 'timeout', 'cafile']
        for o in auth_opts + sess_opts:
            self.assertIn(o, self.cfg.conf[TESTGROUP])
        self.assertEqual('password', self.cfg.conf[TESTGROUP]['auth_type'])

    @mock.patch.object(keystone, '_get_auth')
    def test_get_session(self, auth_mock):
        keystone.register_auth_opts(TESTGROUP)
        self.cfg.config(group=TESTGROUP,
                        cafile='/path/to/ca/file')
        auth1 = mock.Mock()
        auth_mock.return_value = auth1
        sess = keystone.get_session(TESTGROUP)
        self.assertEqual('/path/to/ca/file', sess.verify)
        self.assertEqual(auth1, sess.auth)

    @mock.patch('keystoneauth1.loading.load_auth_from_conf_options')
    @mock.patch.object(keystone, '_get_legacy_auth')
    def test__get_auth(self, legacy_mock, load_mock):
        auth1 = mock.Mock()
        load_mock.side_effect = [
            auth1,
            None,
            kaexc.MissingRequiredOptions([kaloading.Opt('spam')])]
        auth2 = mock.Mock()
        legacy_mock.return_value = auth2
        self.assertEqual(auth1, keystone._get_auth(TESTGROUP))
        self.assertEqual(auth2, keystone._get_auth(TESTGROUP))
        self.assertEqual(auth2, keystone._get_auth(TESTGROUP))

    @mock.patch('keystoneauth1.loading._plugins.identity.generic.Password.'
                'load_from_options')
    def test__get_legacy_auth(self, load_mock):
        self.cfg.register_opts(
            [cfg.StrOpt('identity_url'),
             cfg.StrOpt('old_user'),
             cfg.StrOpt('old_password')],
            group=TESTGROUP)
        self.cfg.config(group=TESTGROUP,
                        identity_url='http://fake:5000/v3',
                        old_password='ham',
                        old_user='spam')
        options = [cfg.StrOpt('old_tenant_name', default='fake'),
                   cfg.StrOpt('old_user')]
        mapping = {'username': 'old_user',
                   'password': 'old_password',
                   'auth_url': 'identity_url',
                   'tenant_name': 'old_tenant_name'}

        keystone._get_legacy_auth(TESTGROUP, mapping, options)
        load_mock.assert_called_once_with(username='spam',
                                          password='ham',
                                          tenant_name='fake',
                                          user_domain_id='default',
                                          project_domain_id='default',
                                          auth_url='http://fake:5000/v3')

    def test__is_api_v3(self):
        cases = ((False, 'http://fake:5000', None),
                 (False, 'http://fake:5000/v2.0', None),
                 (True, 'http://fake:5000/v3', None),
                 (True, 'http://fake:5000', '3'),
                 (True, 'http://fake:5000', 'v3.0'))
        for case in cases:
            result, url, version = case
            self.assertEqual(result, keystone._is_apiv3(url, version))

    def test_add_auth_options(self):
        group, opts = keystone.add_auth_options([], TESTGROUP)[0]
        self.assertEqual(TESTGROUP, group)
        # check that there is no duplicates
        names = {o.dest for o in opts}
        self.assertEqual(len(names), len(opts))
        # NOTE(pas-ha) checking for most standard auth and session ones only
        expected = {'timeout', 'insecure', 'cafile', 'certfile', 'keyfile',
                    'auth_type', 'auth_url', 'username', 'password',
                    'tenant_name', 'project_name', 'trust_id',
                    'domain_id', 'user_domain_id', 'project_domain_id'}
        self.assertTrue(expected.issubset(names))
