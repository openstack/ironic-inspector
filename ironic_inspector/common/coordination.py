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

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log
import tooz
from tooz import coordination

from ironic_inspector import utils

CONF = cfg.CONF
LOG = log.getLogger(__name__)

COORDINATION_PREFIX = 'ironic_inspector'
COORDINATION_GROUP_NAME = '.'.join([COORDINATION_PREFIX, 'service_group'])
LOCK_PREFIX = 'ironic_inspector.'


class Coordinator(object):
    """Tooz coordination wrapper."""

    group_name = COORDINATION_GROUP_NAME.encode('ascii')
    lock_prefix = LOCK_PREFIX

    def __init__(self, prefix=None):
        """Creates a coordinator instance for service coordination.

        :param prefix: The prefix to be part of the member id of the service.
                       Different types of services on the same host should use
                       different prefix to work properly.
        """
        self.coordinator = None
        self.started = False
        self.prefix = prefix if prefix else 'default'
        self.is_leader = False
        self.supports_election = True

    def start(self, heartbeat=True):
        """Start coordinator.

        :param heartbeat: Whether spawns a new thread to keep heartbeating with
                          the tooz backend. Unless there is periodic task to
                          do heartbeat manually, it should be always set to
                          True.
        """
        if self.started:
            return

        member_id = '.'.join([COORDINATION_PREFIX, self.prefix,
                             CONF.host]).encode('ascii')
        self.coordinator = coordination.get_coordinator(
            CONF.coordination.backend_url, member_id)
        self.coordinator.start(start_heart=heartbeat)
        self.started = True
        LOG.debug('Coordinator started successfully.')

    def stop(self):
        """Disconnect from coordination backend and stop heartbeat."""
        if self.started:
            try:
                self.coordinator.stop()
            except Exception as e:
                LOG.error('Failed to stop coordinator: %s', e)
            self.coordinator = None
            self.started = False
            LOG.debug('Coordinator stopped successfully')

    def _validate_state(self):
        if not self.started:
            raise utils.Error('Coordinator should be started before '
                              'executing coordination actions.')

    def _create_group(self):
        try:
            request = self.coordinator.create_group(self.group_name)
            request.get()
        except coordination.GroupAlreadyExist:
            LOG.debug('Group %s already exists.', self.group_name)

    def _join_election(self):
        self.is_leader = False

        def _when_elected(event):
            LOG.info('This conductor instance is a group leader now.')
            self.is_leader = True

        try:
            self.coordinator.watch_elected_as_leader(
                self.group_name, _when_elected)
            self.coordinator.run_elect_coordinator()
        except tooz.NotImplemented:
            LOG.warning('The coordination backend does not support leader '
                        'elections, assuming we are a leader. This is '
                        'deprecated, please use a supported backend.')
            self.is_leader = True
            self.supports_election = False

    def join_group(self):
        """Join service group."""
        self._validate_state()
        try:
            request = self.coordinator.join_group(self.group_name)
            request.get()
        except coordination.GroupNotCreated:
            self._create_group()
            request = self.coordinator.join_group(self.group_name)
            request.get()
        except coordination.MemberAlreadyExist:
            pass

        self._join_election()
        LOG.debug('Joined group %s', self.group_name)

    def leave_group(self):
        """Leave service group"""
        self._validate_state()
        try:
            request = self.coordinator.leave_group(self.group_name)
            request.get()
            LOG.debug('Left group %s', self.group_name)
        except coordination.MemberNotJoined:
            LOG.debug('Leaving a non-existing group.')

    def get_members(self):
        """Get members in the service group."""
        self._validate_state()
        try:
            result = self.coordinator.get_members(self.group_name)
            return result.get()
        except coordination.GroupNotCreated:
            # If the group does not exist, there should be no members in it.
            return set()

    def get_lock(self, uuid):
        """Get lock for node uuid."""
        self._validate_state()
        lock_name = (self.lock_prefix + uuid).encode('ascii')
        return self.coordinator.get_lock(lock_name)

    def run_elect_coordinator(self):
        """Trigger a new leader election."""
        if self.supports_election:
            LOG.debug('Starting leader election')
            self.coordinator.run_elect_coordinator()
            LOG.debug('Finished leader election')
        else:
            LOG.warning('The coordination backend does not support leader '
                        'elections, assuming we are a leader. This is '
                        'deprecated, please use a supported backend.')
            self.is_leader = True


_COORDINATOR = None


@lockutils.synchronized('inspector_coordinator')
def get_coordinator(prefix=None):
    global _COORDINATOR
    if _COORDINATOR is None:
        _COORDINATOR = Coordinator(prefix=prefix)
    return _COORDINATOR
