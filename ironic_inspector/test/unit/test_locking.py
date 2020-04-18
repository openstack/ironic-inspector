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

from unittest import mock

from oslo_config import cfg

from ironic_inspector.common import coordination
from ironic_inspector.common import locking
from ironic_inspector.test import base as test_base

CONF = cfg.CONF


@mock.patch.object(locking, 'InternalLock', autospec=True)
@mock.patch.object(locking, 'ToozLock', autospec=True)
class TestGetLock(test_base.NodeTest):
    def test_get_lock_internal(self, mock_tooz, mock_internal):
        locking.get_lock(self.node.uuid)

        mock_internal.assert_called_once_with(self.node.uuid)
        mock_tooz.assert_not_called()

    @mock.patch.object(coordination, 'get_coordinator', autospec=True)
    def test_get_lock_tooz(self, mock_get_coord, mock_tooz, mock_internal):
        CONF.set_override('standalone', False)
        mock_lock = mock.Mock()
        coordinator = mock.Mock()
        coordinator.get_lock.return_value = mock_lock
        mock_get_coord.return_value = coordinator

        locking.get_lock(self.node.uuid)

        mock_tooz.assert_called_once_with(mock_lock)
        mock_internal.assert_not_called()


class TestInternalLock(test_base.NodeTest):
    def setUp(self):
        super(TestInternalLock, self).setUp()
        self.mock_lock = mock.MagicMock()
        self.mock_lock.acquire.return_value = True

    @mock.patch.object(locking, 'lockutils', autospec=True)
    def test_init_lock(self, mock_lockutils):
        locking.InternalLock(self.node.uuid)
        mock_lockutils.internal_lock.assert_called_with(
            'node-%s' % self.node.uuid, mock.ANY)

    def test_acquire(self):
        lock = locking.InternalLock(self.node.uuid)
        lock._lock = self.mock_lock
        lock.acquire()
        self.mock_lock.acquire.assert_called_once_with(blocking=True)

    def test_release(self):
        lock = locking.ToozLock(self.mock_lock)
        self.mock_lock._locked = True

        lock.release()

        self.mock_lock.release.assert_called_once_with()

    def test_context(self):
        lock = locking.InternalLock(self.node.uuid)
        lock._lock = self.mock_lock

        with lock:
            self.mock_lock.acquire.assert_called_once_with()

        self.mock_lock.release.assert_called_once_with()


class TestToozLock(test_base.NodeTest):
    def setUp(self):
        super(TestToozLock, self).setUp()
        self.mock_lock = mock.MagicMock()
        self.mock_lock.acquire.return_value = True
        self.mock_lock.acquired = False

    def test_acquire(self):
        lock = locking.ToozLock(self.mock_lock)
        lock.acquire()
        self.mock_lock.acquire.assert_called_once_with(blocking=True)

    def test_release(self):
        self.mock_lock.acquired = True
        lock = locking.ToozLock(self.mock_lock)

        lock.release()

        self.mock_lock.release.assert_called_once_with()

    def test_context(self):
        lock = locking.ToozLock(self.mock_lock)

        with lock:
            self.mock_lock.acquire.assert_called_once_with()

        self.mock_lock.release.assert_called_once_with()
