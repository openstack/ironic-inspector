# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from unittest import mock

import fixtures
from oslo_config import cfg
import tooz

from ironic_inspector.common import coordination
from ironic_inspector.test import base
from ironic_inspector import utils

CONF = cfg.CONF


@mock.patch.object(coordination, 'Coordinator', autospec=True)
class TestGetCoordinator(base.BaseTest):
    def setUp(self):
        super(TestGetCoordinator, self).setUp()
        coordination._COORDINATOR = None

    def test_get(self, mock_coordinator):

        coordination.get_coordinator()
        mock_coordinator.assert_called_once_with(prefix=None)

    def test_get_with_prefix(self, mock_coordinator):
        coordination.get_coordinator(prefix='conductor')
        mock_coordinator.assert_called_once_with(prefix='conductor')


class TestCoordinator(base.BaseTest):
    def setUp(self):
        super(TestCoordinator, self).setUp()
        self.coordinator = coordination.Coordinator(prefix='test')
        self.mock_driver = self.useFixture(
            fixtures.MockPatchObject(tooz.coordination, 'CoordinationDriver',
                                     autospec=True)).mock
        self.mock_get_coordinator = self.useFixture(
            fixtures.MockPatchObject(tooz.coordination, 'get_coordinator',
                                     autospec=True)).mock
        self.mock_get_coordinator.return_value = self.mock_driver
        self.group_name = coordination.COORDINATION_GROUP_NAME.encode('ascii')

    def test_start(self):
        CONF.set_override('backend_url', 'memcached://1.2.3.4:11211',
                          'coordination')
        CONF.set_override('host', '1.2.3.5')
        self.coordinator.start()
        self.mock_get_coordinator.assert_called_once_with(
            'memcached://1.2.3.4:11211', b'ironic_inspector.test.1.2.3.5')
        self.assertTrue(self.coordinator.started)
        self.mock_driver.start.assert_called_once_with(start_heart=True)

    def test_stop(self):
        self.coordinator.started = True
        self.coordinator.coordinator = mock.MagicMock()
        self.coordinator.stop()
        self.assertFalse(self.coordinator.started)

    def test__create_group(self):
        self.coordinator.start()
        self.coordinator._create_group()
        self.mock_driver.create_group.assert_called_once_with(self.group_name)

    def test_join_group(self):
        self.coordinator.start()
        self.coordinator.join_group()
        self.mock_driver.join_group.assert_called_once_with(self.group_name)

    def test_join_group_not_exist(self):
        self.coordinator.start()
        self.mock_driver.join_group.side_effect = [
            tooz.coordination.GroupNotCreated('a group'), mock.Mock()]
        self.coordinator.join_group()
        self.mock_driver.create_group.assert_called_once_with(self.group_name)
        self.mock_driver.join_group.assert_has_calls([
            mock.call(self.group_name), mock.call(self.group_name)])

    def test_leave_group(self):
        self.coordinator.start()
        self.coordinator.leave_group()
        self.mock_driver.leave_group.assert_called_once_with(self.group_name)

    def test_get_members(self):
        self.coordinator.start()
        mock_resp = mock.Mock()
        mock_resp.get.return_value = {'host1', 'host2'}
        self.mock_driver.get_members.return_value = mock_resp
        members = self.coordinator.get_members()
        self.assertEqual(members, {'host1', 'host2'})
        self.mock_driver.get_members.assert_called_once_with(self.group_name)

    def test_get_members_no_such_group(self):
        self.coordinator.start()
        self.mock_driver.get_members.side_effect = (
            tooz.coordination.GroupNotCreated('a group'))
        self.assertEqual(self.coordinator.get_members(), set())

    def test_get_lock(self):
        self.coordinator.start()
        self.coordinator.get_lock('fake-node')
        self.mock_driver.get_lock.assert_called_once_with(
            b'ironic_inspector.fake-node')

    def test_invalid_state(self):
        self.assertRaisesRegex(utils.Error, 'Coordinator should be started',
                               self.coordinator.join_group)
        self.assertRaisesRegex(utils.Error, 'Coordinator should be started',
                               self.coordinator.leave_group)
        self.assertRaisesRegex(utils.Error, 'Coordinator should be started',
                               self.coordinator.get_members)
        self.assertRaisesRegex(utils.Error, 'Coordinator should be started',
                               self.coordinator.get_lock, 'fake id')
