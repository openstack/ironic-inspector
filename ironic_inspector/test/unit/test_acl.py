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

import datetime
from unittest import mock
import uuid

import fixtures
from keystoneauth1.fixture import v3 as v3_token
from keystonemiddleware import auth_token
from oslo_config import cfg
from oslo_context import context as oslo_context
import oslo_messaging as messaging
from oslo_utils import uuidutils

from ironic_inspector.common import rpc
import ironic_inspector.conf
from ironic_inspector import introspection_state as istate
from ironic_inspector import main
from ironic_inspector import node_cache
from ironic_inspector.test import base as test_base

CONF = ironic_inspector.conf.CONF


# Tokens for RBAC policy tests
ADMIN_TOKEN = uuid.uuid4().hex
admin_context = oslo_context.RequestContext(
    user_id=ADMIN_TOKEN,
    roles=['admin', 'member', 'reader'],
)

MANAGER_TOKEN = uuid.uuid4().hex
manager_context = oslo_context.RequestContext(
    user_id=MANAGER_TOKEN,
    roles=['manager', 'member', 'reader'],
)

MEMBER_TOKEN = uuid.uuid4().hex
member_context = oslo_context.RequestContext(
    user_id=MEMBER_TOKEN,
    roles=['member', 'reader'],
)

READER_TOKEN = uuid.uuid4().hex
reader_context = oslo_context.RequestContext(
    user_id=READER_TOKEN,
    roles=['reader'],
)

NO_ROLE_TOKEN = uuid.uuid4().hex
no_role_context = oslo_context.RequestContext(
    user_id=READER_TOKEN,
    roles=[],
)

SERVICE_TOKEN = uuid.uuid4().hex
service_context = oslo_context.RequestContext(
    user_id=SERVICE_TOKEN,
    roles=['service']
)

# Tokens for deprecated policy tests
BM_ADMIN_TOKEN = uuid.uuid4().hex
bm_admin_context = oslo_context.RequestContext(
    user_id=BM_ADMIN_TOKEN,
    roles=['baremetal_admin'],
)
BM_OBSERVER_TOKEN = uuid.uuid4().hex
bm_observer_context = oslo_context.RequestContext(
    user_id=BM_OBSERVER_TOKEN,
    roles=['baremetal_observer'],
)


USERS = {
    ADMIN_TOKEN: admin_context.to_dict(),
    MANAGER_TOKEN: manager_context.to_dict(),
    SERVICE_TOKEN: service_context.to_dict(),
    MEMBER_TOKEN: member_context.to_dict(),
    READER_TOKEN: reader_context.to_dict(),
    NO_ROLE_TOKEN: no_role_context.to_dict(),
    BM_ADMIN_TOKEN: bm_admin_context.to_dict(),
    BM_OBSERVER_TOKEN: bm_observer_context.to_dict(),
}


class BasePolicyTest(test_base.BaseTest):

    system_scope = False

    def init_app(self):
        CONF.set_override('auth_strategy', 'keystone')
        main._app.testing = True
        self.app = main.get_app().test_client()

    def setUp(self):
        super(BasePolicyTest, self).setUp()
        self.init_app()
        self.uuid = uuidutils.generate_uuid()
        self.rpc_get_client_mock = self.useFixture(
            fixtures.MockPatchObject(rpc, 'get_client', autospec=True)).mock
        self.client_mock = mock.MagicMock(spec=messaging.RPCClient)
        self.rpc_get_client_mock.return_value = self.client_mock

        self.fake_token = None
        mock_auth = mock.patch.object(
            auth_token.AuthProtocol, 'process_request',
            autospec=True)
        self.mock_auth = mock_auth.start()
        self.addCleanup(mock_auth.stop)
        self.mock_auth.side_effect = self._fake_process_request

        mock_get = mock.patch.object(node_cache, 'get_node', autospec=True)
        get = mock_get.start()
        self.addCleanup(mock_get.stop)
        get.return_value = node_cache.NodeInfo(
            uuid=self.uuid,
            started_at=datetime.datetime(1, 1, 1),
            state=istate.States.processing)

    def _fake_process_request(self, request, meow):
        if self.fake_token:
            request.user_token_valid = True
            request.user_token = True
            # is this right?!?
            request.token_info = self.fake_token
            request.auth_token = v3_token.Token(
                user_id=self.fake_token['user'])
        else:
            # Because of this, the user will always get a 403 in testing, even
            # if the API would normally return a 401 if a token is valid
            request.user_token_valid = False

    def set_token(self, token):
        self.fake_token = USERS[token]
        headers = {
            'X-Auth-Token': token,
            'X-Roles': ','.join(self.fake_token['roles'])
        }
        if self.system_scope:
            headers['OpenStack-System-Scope'] = 'all'
        return headers

    def assert_status(self, status_code, token, request_func, path, data=None):
        headers = self.set_token(token)
        res = request_func(path, headers=headers, data=data)
        self.assertEqual(status_code, res.status_code)


class TestACLDeprecated(BasePolicyTest):

    def setUp(self):
        super(TestACLDeprecated, self).setUp()
        cfg.CONF.set_override('enforce_scope', False, group='oslo_policy')
        cfg.CONF.set_override('enforce_new_defaults', False,
                              group='oslo_policy')

    def test_root_baremetal_admin(self):
        self.assert_status(200, BM_ADMIN_TOKEN, self.app.get, '/')
        self.assert_status(200, BM_ADMIN_TOKEN, self.app.get, '/v1')

    def test_root_baremetal_observer(self):
        self.assert_status(200, BM_OBSERVER_TOKEN, self.app.get, '/')
        self.assert_status(200, BM_OBSERVER_TOKEN, self.app.get, '/v1')

    def test_root_system_no_role(self):
        self.assert_status(200, NO_ROLE_TOKEN, self.app.get, '/')
        self.assert_status(200, NO_ROLE_TOKEN, self.app.get, '/v1')

    def test_introspect_baremetal_admin(self):
        self.assert_status(202, BM_ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_baremetal_admin(self):
        self.assert_status(202, BM_ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_status_baremetal_admin(self):
        self.assert_status(200, BM_ADMIN_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_baremetal_observer(self):
        self.assert_status(200, BM_OBSERVER_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_list_baremetal_admin(self):
        self.assert_status(200, BM_ADMIN_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_baremetal_observer(self):
        self.assert_status(200, BM_OBSERVER_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_data_baremetal_admin(self):
        self.assert_status(404, BM_ADMIN_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_unprocessed_baremetal_admin(self):
        self.assert_status(400, BM_ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_rule_list_baremetal_admin(self):
        self.assert_status(200, BM_ADMIN_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_get_baremetal_admin(self):
        self.assert_status(404, BM_ADMIN_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_delete_all_baremetal_admin(self):
        self.assert_status(204, BM_ADMIN_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_baremetal_admin(self):
        self.assert_status(404, BM_ADMIN_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_create_baremetal_admin(self):
        self.assert_status(500, BM_ADMIN_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_baremetal_observer(self):
        self.assert_status(403, BM_OBSERVER_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })


class TestRBACScoped(BasePolicyTest):

    system_scope = True

    def setUp(self):
        super(TestRBACScoped, self).setUp()
        cfg.CONF.set_override('enforce_scope', True, group='oslo_policy')
        cfg.CONF.set_override('enforce_new_defaults', True,
                              group='oslo_policy')

    def test_root_system_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get, '/')
        self.assert_status(200, ADMIN_TOKEN, self.app.get, '/v1')

    def test_root_system_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get, '/')
        self.assert_status(200, SERVICE_TOKEN, self.app.get, '/v1')

    def test_root_system_member(self):
        self.assert_status(200, MEMBER_TOKEN, self.app.get, '/')
        self.assert_status(200, MEMBER_TOKEN, self.app.get, '/v1')

    def test_root_system_reader(self):
        self.assert_status(200, READER_TOKEN, self.app.get, '/')
        self.assert_status(200, READER_TOKEN, self.app.get, '/v1')

    def test_root_system_no_role(self):
        self.assert_status(200, NO_ROLE_TOKEN, self.app.get, '/')
        self.assert_status(200, NO_ROLE_TOKEN, self.app.get, '/v1')

    def test_introspect_system_admin(self):
        self.assert_status(202, ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_system_service(self):
        self.assert_status(202, SERVICE_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_system_admin(self):
        self.assert_status(202, ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_system_service(self):
        self.assert_status(202, SERVICE_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_status_system_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_system_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_system_member(self):
        self.assert_status(200, MEMBER_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_system_reader(self):
        self.assert_status(200, READER_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_list_system_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_system_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_system_member(self):
        self.assert_status(200, MEMBER_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_system_reader(self):
        self.assert_status(200, READER_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_data_system_admin(self):
        self.assert_status(404, ADMIN_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_system_service(self):
        self.assert_status(404, SERVICE_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_unprocessed_system_admin(self):
        self.assert_status(400, ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_system_service(self):
        self.assert_status(400, SERVICE_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_rule_list_system_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_system_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_get_system_admin(self):
        self.assert_status(404, ADMIN_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_system_service(self):
        self.assert_status(404, SERVICE_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_delete_all_system_admin(self):
        self.assert_status(204, ADMIN_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_system_service(self):
        self.assert_status(204, SERVICE_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_system_admin(self):
        self.assert_status(404, ADMIN_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_system_service(self):
        self.assert_status(404, SERVICE_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_create_system_admin(self):
        self.assert_status(500, ADMIN_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_system_service(self):
        self.assert_status(500, SERVICE_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_system_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_system_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })


class TestRBACProjectScope(BasePolicyTest):

    system_scope = False

    def setUp(self):
        super(TestRBACProjectScope, self).setUp()
        cfg.CONF.set_override('enforce_scope', True, group='oslo_policy')
        cfg.CONF.set_override('enforce_new_defaults', True,
                              group='oslo_policy')

    def test_root_project_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get, '/')
        self.assert_status(200, ADMIN_TOKEN, self.app.get, '/v1')

    def test_root_project_manager(self):
        self.assert_status(200, MANAGER_TOKEN, self.app.get, '/')
        self.assert_status(200, MANAGER_TOKEN, self.app.get, '/v1')

    def test_root_project_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get, '/')
        self.assert_status(200, SERVICE_TOKEN, self.app.get, '/v1')

    def test_root_project_member(self):
        self.assert_status(200, MEMBER_TOKEN, self.app.get, '/')
        self.assert_status(200, MEMBER_TOKEN, self.app.get, '/v1')

    def test_root_project_reader(self):
        self.assert_status(200, READER_TOKEN, self.app.get, '/')
        self.assert_status(200, READER_TOKEN, self.app.get, '/v1')

    def test_root_project_no_role(self):
        self.assert_status(200, NO_ROLE_TOKEN, self.app.get, '/')
        self.assert_status(200, NO_ROLE_TOKEN, self.app.get, '/v1')

    def test_introspect_project_admin(self):
        self.assert_status(202, ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_project_service(self):
        self.assert_status(202, SERVICE_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/introspection/%s' % self.uuid)

    def test_introspect_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_project_admin(self):
        self.assert_status(202, ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_project_service(self):
        self.assert_status(202, SERVICE_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_abort_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/introspection/%s/abort' % self.uuid)

    def test_status_project_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_project_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_status_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/introspection/%s' % self.uuid)

    def test_list_project_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_project_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_list_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/introspection')

    def test_data_project_admin(self):
        self.assert_status(404, ADMIN_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_project_service(self):
        self.assert_status(404, SERVICE_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/introspection/%s/data' % self.uuid)

    def test_data_unprocessed_project_admin(self):
        self.assert_status(400, ADMIN_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_project_service(self):
        self.assert_status(400, SERVICE_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_data_unprocessed_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/introspection/%s/data/unprocessed' % self.uuid,
                           data={'foo': 'bar'})

    def test_rule_list_project_admin(self):
        self.assert_status(200, ADMIN_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_project_service(self):
        self.assert_status(200, SERVICE_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_list_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/rules')

    def test_rule_get_project_admin(self):
        self.assert_status(404, ADMIN_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_project_service(self):
        self.assert_status(404, SERVICE_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_get_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.get,
                           '/v1/rules/foo')

    def test_rule_delete_all_project_admin(self):
        self.assert_status(204, ADMIN_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_project_service(self):
        self.assert_status(204, SERVICE_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_all_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.delete,
                           '/v1/rules')

    def test_rule_delete_project_admin(self):
        self.assert_status(404, ADMIN_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_project_service(self):
        self.assert_status(404, SERVICE_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_delete_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.delete,
                           '/v1/rules/foo')

    def test_rule_create_project_admin(self):
        self.assert_status(500, ADMIN_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_project_manager(self):
        self.assert_status(403, MANAGER_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_project_service(self):
        self.assert_status(500, SERVICE_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_project_member(self):
        self.assert_status(403, MEMBER_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })

    def test_rule_create_project_reader(self):
        self.assert_status(403, READER_TOKEN, self.app.post,
                           '/v1/rules',
                           data={
                               'uuid': self.uuid,
                               'conditions': 'cond',
                               'actions': 'act'
                           })
