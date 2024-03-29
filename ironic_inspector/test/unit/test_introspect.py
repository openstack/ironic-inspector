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

import collections
import time
from unittest import mock

import fixtures
from openstack import exceptions as os_exc
from oslo_config import cfg

from ironic_inspector.common import ironic as ir_utils
from ironic_inspector import introspect
from ironic_inspector import introspection_state as istate
from ironic_inspector import node_cache
from ironic_inspector.pxe_filter import base as pxe_filter
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = cfg.CONF


class BaseTest(test_base.NodeTestBase):
    def setUp(self):
        super(BaseTest, self).setUp()
        introspect._LAST_INTROSPECTION_TIME = 0
        self.node.power_state = 'power off'
        self.ports = [mock.Mock(address=m) for m in self.macs]
        self.ports_dict = collections.OrderedDict((p.address, p)
                                                  for p in self.ports)
        self.node_info = mock.Mock(uuid=self.uuid, options={})
        self.node_info.ports.return_value = self.ports_dict
        self.node_info.node.return_value = self.node

        driver_fixture = self.useFixture(fixtures.MockPatchObject(
            pxe_filter, 'driver', autospec=True))
        driver_mock = driver_fixture.mock.return_value
        self.sync_filter_mock = driver_mock.sync

        self.async_exc = None
        executor_fixture = self.useFixture(fixtures.MockPatchObject(
            utils, 'executor', autospec=True))
        self.submit_mock = executor_fixture.mock.return_value.submit
        self.submit_mock.side_effect = self._submit

    def _prepare(self, client_mock):
        cli = client_mock.return_value
        cli.get_node.return_value = self.node
        cli.validate_node.return_value = mock.Mock(power={'result': True})
        return cli

    def _submit(self, func, *args, **kwargs):
        if self.async_exc:
            self.assertRaisesRegex(*self.async_exc, func, *args, **kwargs)
        else:
            return func(*args, **kwargs)


@mock.patch.object(node_cache, 'start_introspection', autospec=True)
@mock.patch.object(ir_utils, 'get_client', autospec=True)
class TestIntrospect(BaseTest):
    def test_ok(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)
        cli.validate_node.assert_called_once_with(self.uuid, required='power')

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with(
            'mac', self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        cli.set_node_boot_device.assert_called_once_with(
            self.uuid, 'pxe', persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_ok_retries_node_locked(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info
        cli.set_node_power_state.side_effect = [
            os_exc.ConflictException("Locked"),
            None]
        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)
        cli.validate_node.assert_called_once_with(self.uuid, required='power')

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with(
            'mac', self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        cli.set_node_boot_device.assert_called_once_with(
            self.uuid, 'pxe', persistent=False)
        cli.set_node_power_state.assert_has_calls([
            mock.call(self.uuid, 'rebooting'),
            mock.call(self.uuid, 'rebooting')])

        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    @mock.patch.object(ir_utils, 'get_ipmi_address', autospec=True)
    def test_resolved_bmc_address(self, ipmi_mock, client_mock, start_mock):
        self.node.driver_info['ipmi_address'] = 'example.com'
        addresses = ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']
        ipmi_mock.return_value = ('example.com',) + tuple(addresses)
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)
        cli.validate_node.assert_called_once_with(self.uuid, required='power')

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=addresses,
                                           manage_boot=True,
                                           ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with('mac',
                                                             self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_loopback_bmc_address(self, client_mock, start_mock):
        self.node.driver_info['ipmi_address'] = '127.0.0.1'
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)
        cli.validate_node.assert_called_once_with(self.uuid, required='power')

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[],
                                           manage_boot=True,
                                           ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with('mac',
                                                             self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_ok_ilo_and_drac(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        for name in ('ilo_address', 'drac_host'):
            self.node.driver_info = {name: self.bmc_address}
            introspect.introspect(self.node.uuid)

        start_mock.assert_called_with(self.uuid,
                                      bmc_address=[self.bmc_address],
                                      manage_boot=True,
                                      ironic=cli)

    def test_power_failure(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        cli.set_node_power_state.side_effect = os_exc.BadRequestException()
        start_mock.return_value = self.node_info

        self.async_exc = (utils.Error, 'Failed to power on')
        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        power_call = mock.call(self.uuid, 'rebooting')
        cli.set_node_power_state.assert_has_calls([
            power_call, power_call, power_call, power_call, power_call])
        start_mock.return_value.finished.assert_called_once_with(
            introspect.istate.Events.error, error=mock.ANY)
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_unexpected_error(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info
        self.sync_filter_mock.side_effect = RuntimeError()

        self.async_exc = (RuntimeError, '.*')
        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        self.assertFalse(cli.set_node_boot_device.called)
        start_mock.return_value.finished.assert_called_once_with(
            introspect.istate.Events.error, error=mock.ANY)
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_set_boot_device_failure(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        cli.set_node_boot_device.side_effect = os_exc.BadRequestException()
        start_mock.return_value = self.node_info

        self.async_exc = (utils.Error, 'Failed to set boot device')
        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        dev_call = mock.call(self.uuid, 'pxe', persistent=False)
        cli.set_node_boot_device.assert_has_calls([
            dev_call, dev_call, dev_call, dev_call, dev_call])
        cli.set_node_power_state.assert_not_called()
        start_mock.return_value.finished.assert_called_once_with(
            introspect.istate.Events.error, error=mock.ANY)
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_no_macs(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        self.node_info.ports.return_value = []
        start_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid)

        self.node_info.ports.assert_called_once_with()

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        self.assertFalse(self.node_info.add_attribute.called)
        self.assertFalse(self.sync_filter_mock.called)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')

    def test_forced_persistent_boot(self, client_mock, start_mock):
        self.node.driver_info['force_persistent_boot_device'] = 'Always'
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)
        cli.validate_node.assert_called_once_with(self.uuid,
                                                  required='power')

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with('mac',
                                                             self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=True)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_forced_persistent_boot_compat(self, client_mock, start_mock):
        self.node.driver_info['force_persistent_boot_device'] = 'true'
        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid)

        cli.get_node.assert_called_once_with(self.uuid)
        cli.validate_node.assert_called_once_with(self.uuid,
                                                  required='power')

        start_mock.assert_called_once_with(self.uuid,
                                           bmc_address=[self.bmc_address],
                                           manage_boot=True,
                                           ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with('mac',
                                                             self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=True)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_no_lookup_attrs(self, client_mock, start_mock):
        cli = self._prepare(client_mock)
        self.node_info.ports.return_value = []
        start_mock.return_value = self.node_info
        self.node_info.attributes = {}

        self.async_exc = (utils.Error, 'No lookup attributes')
        introspect.introspect(self.uuid)

        self.node_info.ports.assert_called_once_with()
        self.node_info.finished.assert_called_once_with(
            introspect.istate.Events.error, error=mock.ANY)
        self.assertEqual(0, self.sync_filter_mock.call_count)
        self.assertEqual(0, cli.set_node_power_state.call_count)
        self.node_info.acquire_lock.assert_called_once_with()
        self.node_info.release_lock.assert_called_once_with()

    def test_no_lookup_attrs_with_node_not_found_hook(self, client_mock,
                                                      start_mock):
        CONF.set_override('node_not_found_hook', 'example', 'processing')
        cli = self._prepare(client_mock)
        self.node_info.ports.return_value = []
        start_mock.return_value = self.node_info
        self.node_info.attributes = {}

        introspect.introspect(self.uuid)

        self.node_info.ports.assert_called_once_with()
        self.assertFalse(self.node_info.finished.called)
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')

    def test_failed_to_get_node(self, client_mock, start_mock):
        cli = client_mock.return_value
        cli.get_node.side_effect = os_exc.NotFoundException()
        self.assertRaisesRegex(utils.Error,
                               'Node %s was not found' % self.uuid,
                               introspect.introspect, self.uuid)

        cli.get_node.side_effect = os_exc.BadRequestException()
        self.assertRaisesRegex(utils.Error,
                               'Cannot get node %s: Error' % self.uuid,
                               introspect.introspect, self.uuid)

        self.assertEqual(0, self.node_info.ports.call_count)
        self.assertEqual(0, self.sync_filter_mock.call_count)
        self.assertEqual(0, cli.set_node_power_state.call_count)
        self.assertFalse(start_mock.called)
        self.assertFalse(self.node_info.acquire_lock.called)

    def test_failed_to_validate_node(self, client_mock, start_mock):
        cli = client_mock.return_value
        cli.get_node.return_value = self.node
        cli.validate_node.side_effect = os_exc.ValidationException()
        self.assertRaisesRegex(
            utils.Error,
            'Failed validation of power interface: ValidationException',
            introspect.introspect, self.uuid)

        cli.validate_node.assert_called_once_with(self.uuid, required='power')
        self.assertEqual(0, self.node_info.ports.call_count)
        self.assertEqual(0, self.sync_filter_mock.call_count)
        self.assertEqual(0, cli.set_node_power_state.call_count)
        self.assertFalse(start_mock.called)
        self.assertFalse(self.node_info.acquire_lock.called)

    def test_wrong_provision_state(self, client_mock, start_mock):
        self.node.provision_state = 'active'
        cli = client_mock.return_value
        cli.get_node.return_value = self.node

        self.assertRaisesRegex(
            utils.Error, 'Invalid provision state for introspection: "active"',
            introspect.introspect, self.uuid)

        self.assertEqual(0, self.node_info.ports.call_count)
        self.assertEqual(0, self.sync_filter_mock.call_count)
        self.assertEqual(0, cli.set_node_power_state.call_count)
        self.assertFalse(start_mock.called)
        self.assertFalse(self.node_info.acquire_lock.called)

    def test_inspect_wait_state_allowed(self, client_mock, start_mock):
        self.node.provision_state = 'inspect wait'
        cli = client_mock.return_value
        cli.get_node.return_value = self.node
        cli.validate_node.return_value = mock.Mock(power={'result': True})

        introspect.introspect(self.uuid)

        self.assertTrue(start_mock.called)

    @mock.patch.object(time, 'time', autospec=True)
    def test_introspection_delay(self, time_mock, client_mock, start_mock):
        time_mock.return_value = 42
        introspect._LAST_INTROSPECTION_TIME = 40
        CONF.set_override('introspection_delay', 10)

        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.uuid)

        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        # updated to the current time.time()
        self.assertEqual(42, introspect._LAST_INTROSPECTION_TIME)

    @mock.patch.object(time, 'time', autospec=True)
    def test_introspection_no_delay_without_manage_boot(self, time_mock,
                                                        client_mock,
                                                        start_mock):
        time_mock.return_value = 42
        introspect._LAST_INTROSPECTION_TIME = 40
        CONF.set_override('introspection_delay', 10)

        self._prepare(client_mock)
        start_mock.return_value = self.node_info
        self.node_info.manage_boot = False

        introspect.introspect(self.uuid, manage_boot=False)

        self.assertFalse(self.sleep_fixture.mock.called)
        # not updated
        self.assertEqual(40, introspect._LAST_INTROSPECTION_TIME)

    @mock.patch.object(time, 'time', autospec=True)
    def test_introspection_delay_not_needed(self, time_mock, client_mock,
                                            start_mock):

        time_mock.return_value = 100
        introspect._LAST_INTROSPECTION_TIME = 40
        CONF.set_override('introspection_delay', 10)

        cli = self._prepare(client_mock)
        start_mock.return_value = self.node_info

        introspect.introspect(self.uuid)

        self.sleep_fixture.mock().assert_not_called()
        cli.set_node_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'rebooting')
        # updated to the current time.time()
        self.assertEqual(100, introspect._LAST_INTROSPECTION_TIME)

    def test_no_manage_boot(self, client_mock, add_mock):
        cli = self._prepare(client_mock)
        self.node_info.manage_boot = False
        add_mock.return_value = self.node_info

        introspect.introspect(self.node.uuid, manage_boot=False)

        cli.get_node.assert_called_once_with(self.uuid)

        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=[self.bmc_address],
                                         manage_boot=False,
                                         ironic=cli)
        self.node_info.ports.assert_called_once_with()
        self.node_info.add_attribute.assert_called_once_with('mac',
                                                             self.macs)
        self.sync_filter_mock.assert_called_with(cli)
        self.assertFalse(cli.validate_node.called)
        self.assertFalse(cli.set_node_boot_device.called)
        self.assertFalse(cli.set_node_power_state.called)


@mock.patch.object(node_cache, 'get_node', autospec=True)
@mock.patch.object(ir_utils, 'get_client', autospec=True)
class TestAbort(BaseTest):
    def setUp(self):
        super(TestAbort, self).setUp()
        self.node_info.started_at = None
        self.node_info.finished_at = None
        # NOTE(milan): node_info.finished() is a mock; no fsm_event call, then
        self.fsm_calls = [
            mock.call(istate.Events.abort, strict=False),
        ]

    def test_ok(self, client_mock, get_mock):
        cli = self._prepare(client_mock)
        get_mock.return_value = self.node_info
        self.node_info.acquire_lock.return_value = True
        self.node_info.started_at = time.time()
        self.node_info.finished_at = None

        introspect.abort(self.node.uuid)

        get_mock.assert_called_once_with(self.uuid, ironic=cli)
        self.node_info.acquire_lock.assert_called_once_with(blocking=False)
        self.sync_filter_mock.assert_called_once_with(cli)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'power off')
        self.node_info.finished.assert_called_once_with(
            introspect.istate.Events.abort_end, error='Canceled by operator')
        self.node_info.fsm_event.assert_has_calls(self.fsm_calls)

    def test_no_manage_boot(self, client_mock, get_mock):
        cli = self._prepare(client_mock)
        get_mock.return_value = self.node_info
        self.node_info.acquire_lock.return_value = True
        self.node_info.started_at = time.time()
        self.node_info.finished_at = None
        self.node_info.manage_boot = False

        introspect.abort(self.node.uuid)

        get_mock.assert_called_once_with(self.uuid, ironic=cli)
        self.node_info.acquire_lock.assert_called_once_with(blocking=False)
        self.sync_filter_mock.assert_called_once_with(cli)
        self.assertFalse(cli.set_node_power_state.called)
        self.node_info.finished.assert_called_once_with(
            introspect.istate.Events.abort_end, error='Canceled by operator')
        self.node_info.fsm_event.assert_has_calls(self.fsm_calls)

    def test_node_not_found(self, client_mock, get_mock):
        cli = self._prepare(client_mock)
        exc = utils.Error('Not found.', code=404)
        get_mock.side_effect = exc

        self.assertRaisesRegex(utils.Error, str(exc),
                               introspect.abort, self.uuid)

        self.assertEqual(0, self.sync_filter_mock.call_count)
        self.assertEqual(0, cli.set_node_power_state.call_count)
        self.assertEqual(0, self.node_info.finished.call_count)
        self.assertEqual(0, self.node_info.fsm_event.call_count)

    def test_node_locked(self, client_mock, get_mock):
        cli = self._prepare(client_mock)
        get_mock.return_value = self.node_info
        self.node_info.acquire_lock.return_value = False
        self.node_info.started_at = time.time()

        self.assertRaisesRegex(utils.Error, 'Node is locked, please, '
                               'retry later', introspect.abort, self.uuid)

        self.assertEqual(0, self.sync_filter_mock.call_count)
        self.assertEqual(0, cli.set_node_power_state.call_count)
        self.assertEqual(0, self.node_info.finished.call_count)
        self.assertEqual(0, self.node_info.fsm_event.call_count)

    def test_firewall_update_exception(self, client_mock, get_mock):
        cli = self._prepare(client_mock)
        get_mock.return_value = self.node_info
        self.node_info.acquire_lock.return_value = True
        self.node_info.started_at = time.time()
        self.node_info.finished_at = None
        self.sync_filter_mock.side_effect = Exception('Boom')

        introspect.abort(self.uuid)

        get_mock.assert_called_once_with(self.uuid, ironic=cli)
        self.node_info.acquire_lock.assert_called_once_with(blocking=False)
        self.sync_filter_mock.assert_called_once_with(cli)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'power off')
        self.node_info.finished.assert_called_once_with(
            introspect.istate.Events.abort_end, error='Canceled by operator')
        self.node_info.fsm_event.assert_has_calls(self.fsm_calls)

    def test_node_power_off_exception(self, client_mock, get_mock):
        cli = self._prepare(client_mock)
        get_mock.return_value = self.node_info
        self.node_info.acquire_lock.return_value = True
        self.node_info.started_at = time.time()
        self.node_info.finished_at = None
        cli.set_node_power_state.side_effect = Exception('BadaBoom')

        introspect.abort(self.uuid)

        get_mock.assert_called_once_with(self.uuid, ironic=cli)
        self.node_info.acquire_lock.assert_called_once_with(blocking=False)
        self.sync_filter_mock.assert_called_once_with(cli)
        cli.set_node_power_state.assert_called_once_with(self.uuid,
                                                         'power off')
        self.node_info.finished.assert_called_once_with(
            introspect.istate.Events.abort_end, error='Canceled by operator')
        self.node_info.fsm_event.assert_has_calls(self.fsm_calls)
