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
import oslo_messaging as messaging

from ironic_inspector.conductor import manager
import ironic_inspector.conf
from ironic_inspector import introspect
from ironic_inspector import process
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = ironic_inspector.conf.CONF


class BaseManagerTest(test_base.NodeTest):
    def setUp(self):
        super(BaseManagerTest, self).setUp()
        self.manager = manager.ConductorManager()
        self.context = {}
        self.token = None


class TestManagerIntrospect(BaseManagerTest):
    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_do_introspect(self, introspect_mock):
        self.manager.do_introspection(self.context, self.uuid, self.token)

        introspect_mock.assert_called_once_with(self.uuid, token=self.token,
                                                manage_boot=True)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_do_introspect_with_manage_boot(self, introspect_mock):
        self.manager.do_introspection(self.context, self.uuid, self.token,
                                      False)

        introspect_mock.assert_called_once_with(self.uuid, token=self.token,
                                                manage_boot=False)

    @mock.patch.object(introspect, 'introspect', autospec=True)
    def test_introspect_failed(self, introspect_mock):
        introspect_mock.side_effect = utils.Error("boom")

        exc = self.assertRaises(messaging.rpc.ExpectedException,
                                self.manager.do_introspection,
                                self.context, self.uuid, self.token)

        self.assertEqual(utils.Error, exc.exc_info[0])
        introspect_mock.assert_called_once_with(self.uuid, token=None,
                                                manage_boot=True)


class TestManagerAbort(BaseManagerTest):
    @mock.patch.object(introspect, 'abort', autospec=True)
    def test_abort_ok(self, abort_mock):
        self.manager.do_abort(self.context, self.uuid, self.token)

        abort_mock.assert_called_once_with(self.uuid, token=self.token)

    @mock.patch.object(introspect, 'abort', autospec=True)
    def test_abort_node_not_found(self, abort_mock):
        abort_mock.side_effect = utils.Error("Not Found.", code=404)

        exc = self.assertRaises(messaging.rpc.ExpectedException,
                                self.manager.do_abort,
                                self.context, self.uuid, self.token)

        self.assertEqual(utils.Error, exc.exc_info[0])
        abort_mock.assert_called_once_with(self.uuid, token=None)

    @mock.patch.object(introspect, 'abort', autospec=True)
    def test_abort_failed(self, abort_mock):
        exc = utils.Error("Locked.", code=409)
        abort_mock.side_effect = exc

        exc = self.assertRaises(messaging.rpc.ExpectedException,
                                self.manager.do_abort,
                                self.context, self.uuid, self.token)

        self.assertEqual(utils.Error, exc.exc_info[0])
        abort_mock.assert_called_once_with(self.uuid, token=None)


@mock.patch.object(process, 'reapply', autospec=True)
class TestManagerReapply(BaseManagerTest):

    def setUp(self):
        super(TestManagerReapply, self).setUp()
        CONF.set_override('store_data', 'swift', 'processing')

    def test_ok(self, reapply_mock):
        self.manager.do_reapply(self.context, self.uuid)
        reapply_mock.assert_called_once_with(self.uuid)

    def test_node_locked(self, reapply_mock):
        exc = utils.Error('Locked.', code=409)
        reapply_mock.side_effect = exc

        exc = self.assertRaises(messaging.rpc.ExpectedException,
                                self.manager.do_reapply,
                                self.context, self.uuid)

        self.assertEqual(utils.Error, exc.exc_info[0])
        self.assertIn('Locked.', str(exc.exc_info[1]))
        self.assertEqual(409, exc.exc_info[1].http_code)
        reapply_mock.assert_called_once_with(self.uuid)

    def test_node_not_found(self, reapply_mock):
        exc = utils.Error('Not found.', code=404)
        reapply_mock.side_effect = exc

        exc = self.assertRaises(messaging.rpc.ExpectedException,
                                self.manager.do_reapply,
                                self.context, self.uuid)

        self.assertEqual(utils.Error, exc.exc_info[0])
        self.assertIn('Not found.', str(exc.exc_info[1]))
        self.assertEqual(404, exc.exc_info[1].http_code)
        reapply_mock.assert_called_once_with(self.uuid)

    def test_generic_error(self, reapply_mock):
        exc = utils.Error('Oops', code=400)
        reapply_mock.side_effect = exc

        exc = self.assertRaises(messaging.rpc.ExpectedException,
                                self.manager.do_reapply,
                                self.context, self.uuid)

        self.assertEqual(utils.Error, exc.exc_info[0])
        self.assertIn('Oops', str(exc.exc_info[1]))
        self.assertEqual(400, exc.exc_info[1].http_code)
        reapply_mock.assert_called_once_with(self.uuid)
