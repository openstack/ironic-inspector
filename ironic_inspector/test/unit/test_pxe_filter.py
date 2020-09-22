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

from automaton import exceptions as automaton_errors
from eventlet import semaphore
import fixtures
from futurist import periodics
from openstack import exceptions as os_exc
from oslo_config import cfg
import stevedore

from ironic_inspector.common import ironic as ir_utils
from ironic_inspector import node_cache
from ironic_inspector.pxe_filter import base as pxe_filter
from ironic_inspector.pxe_filter import interface
from ironic_inspector.test import base as test_base

CONF = cfg.CONF


class TestFilter(pxe_filter.BaseFilter):
    pass


class TestDriverManager(test_base.BaseTest):
    def setUp(self):
        super(TestDriverManager, self).setUp()
        pxe_filter._DRIVER_MANAGER = None
        stevedore_driver_fixture = self.useFixture(fixtures.MockPatchObject(
            stevedore.driver, 'DriverManager', autospec=True))
        self.stevedore_driver_mock = stevedore_driver_fixture.mock

    def test_default(self):
        driver_manager = pxe_filter._driver_manager()
        self.stevedore_driver_mock.assert_called_once_with(
            pxe_filter._STEVEDORE_DRIVER_NAMESPACE,
            name='iptables',
            invoke_on_load=True
        )
        self.assertIsNotNone(driver_manager)
        self.assertIs(pxe_filter._DRIVER_MANAGER, driver_manager)

    def test_pxe_filter_name(self):
        CONF.set_override('driver', 'foo', 'pxe_filter')
        driver_manager = pxe_filter._driver_manager()
        self.stevedore_driver_mock.assert_called_once_with(
            pxe_filter._STEVEDORE_DRIVER_NAMESPACE,
            'foo',
            invoke_on_load=True
        )
        self.assertIsNotNone(driver_manager)
        self.assertIs(pxe_filter._DRIVER_MANAGER, driver_manager)

    def test_default_existing_driver_manager(self):
        pxe_filter._DRIVER_MANAGER = True
        driver_manager = pxe_filter._driver_manager()
        self.stevedore_driver_mock.assert_not_called()
        self.assertIs(pxe_filter._DRIVER_MANAGER, driver_manager)


class TestDriverManagerLoading(test_base.BaseTest):
    def setUp(self):
        super(TestDriverManagerLoading, self).setUp()
        pxe_filter._DRIVER_MANAGER = None

    @mock.patch.object(pxe_filter, 'NoopFilter', autospec=True)
    def test_pxe_filter_driver_loads(self, noop_driver_cls):
        CONF.set_override('driver', 'noop', 'pxe_filter')
        driver_manager = pxe_filter._driver_manager()
        noop_driver_cls.assert_called_once_with()
        self.assertIs(noop_driver_cls.return_value, driver_manager.driver)

    def test_invalid_filter_driver(self):
        CONF.set_override('driver', 'foo', 'pxe_filter')
        self.assertRaisesRegex(stevedore.exception.NoMatches, 'foo',
                               pxe_filter._driver_manager)
        self.assertIsNone(pxe_filter._DRIVER_MANAGER)


class BaseFilterBaseTest(test_base.BaseTest):
    def setUp(self):
        super(BaseFilterBaseTest, self).setUp()
        self.mock_lock = mock.MagicMock(spec=semaphore.BoundedSemaphore)
        self.mock_bounded_semaphore = self.useFixture(
            fixtures.MockPatchObject(semaphore, 'BoundedSemaphore')).mock
        self.mock_bounded_semaphore.return_value = self.mock_lock
        self.driver = TestFilter()

    def assert_driver_is_locked(self):
        """Assert the driver is currently locked and wasn't locked before."""
        self.driver.lock.__enter__.assert_called_once_with()
        self.driver.lock.__exit__.assert_not_called()

    def assert_driver_was_locked_once(self):
        """Assert the driver was locked exactly once before."""
        self.driver.lock.__enter__.assert_called_once_with()
        self.driver.lock.__exit__.assert_called_once_with(None, None, None)

    def assert_driver_was_not_locked(self):
        """Assert the driver was not locked"""
        self.mock_lock.__enter__.assert_not_called()
        self.mock_lock.__exit__.assert_not_called()


class TestLockedDriverEvent(BaseFilterBaseTest):
    def setUp(self):
        super(TestLockedDriverEvent, self).setUp()
        self.mock_fsm_reset_on_error = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'fsm_reset_on_error')).mock
        self.expected_args = (None,)
        self.expected_kwargs = {'foo': None}
        self.mock_fsm = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'fsm')).mock
        (self.driver.fsm_reset_on_error.return_value.
         __enter__.return_value) = self.mock_fsm

    def test_locked_driver_event(self):
        event = 'foo'

        @pxe_filter.locked_driver_event(event)
        def fun(driver, *args, **kwargs):
            self.assertIs(self.driver, driver)
            self.assertEqual(self.expected_args, args)
            self.assertEqual(self.expected_kwargs, kwargs)
            self.assert_driver_is_locked()

        self.assert_driver_was_not_locked()
        fun(self.driver, *self.expected_args, **self.expected_kwargs)

        self.mock_fsm_reset_on_error.assert_called_once_with()
        self.mock_fsm.process_event.assert_called_once_with(event)
        self.assert_driver_was_locked_once()


class TestBaseFilterFsmPrecautions(BaseFilterBaseTest):
    def setUp(self):
        super(TestBaseFilterFsmPrecautions, self).setUp()
        self.mock_fsm = self.useFixture(
            fixtures.MockPatchObject(TestFilter, 'fsm')).mock
        # NOTE(milan): overriding driver so that the patch ^ is applied
        self.mock_bounded_semaphore.reset_mock()
        self.driver = TestFilter()
        self.mock_reset = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'reset')).mock

    def test___init__(self):
        self.assertIs(self.mock_lock, self.driver.lock)
        self.mock_bounded_semaphore.assert_called_once_with()
        self.assertIs(self.mock_fsm, self.driver.fsm)
        self.mock_fsm.initialize.assert_called_once_with(
            start_state=pxe_filter.States.uninitialized)

    def test_fsm_reset_on_error(self):
        with self.driver.fsm_reset_on_error() as fsm:
            self.assertIs(self.mock_fsm, fsm)

        self.mock_reset.assert_not_called()

    def test_fsm_automaton_error(self):
        def fun():
            with self.driver.fsm_reset_on_error():
                raise automaton_errors.NotFound('Oops!')

        self.assertRaisesRegex(pxe_filter.InvalidFilterDriverState,
                               '.*TestFilter.*Oops!', fun)
        self.mock_reset.assert_not_called()

    def test_fsm_reset_on_error_ctx_custom_error(self):
        class MyError(Exception):
            pass

        def fun():
            with self.driver.fsm_reset_on_error():
                raise MyError('Oops!')

        self.assertRaisesRegex(MyError, 'Oops!', fun)
        self.mock_reset.assert_called_once_with()


class TestBaseFilterInterface(BaseFilterBaseTest):
    def setUp(self):
        super(TestBaseFilterInterface, self).setUp()
        self.mock_get_client = self.useFixture(
            fixtures.MockPatchObject(ir_utils, 'get_client')).mock
        self.mock_ironic = mock.Mock()
        self.mock_get_client.return_value = self.mock_ironic
        self.mock_periodic = self.useFixture(
            fixtures.MockPatchObject(periodics, 'periodic')).mock
        self.mock_reset = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'reset')).mock
        self.mock_log = self.useFixture(
            fixtures.MockPatchObject(pxe_filter, 'LOG')).mock
        self.driver.fsm_reset_on_error = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'fsm_reset_on_error')).mock

    def test_init_filter(self):
        self.driver.init_filter()

        self.mock_log.debug.assert_called_once_with(
            'Initializing the PXE filter driver %s', self.driver)
        self.mock_reset.assert_not_called()

    def test_sync(self):
        self.driver.sync(self.mock_ironic)

        self.mock_reset.assert_not_called()

    def test_tear_down_filter(self):
        self.assert_driver_was_not_locked()
        self.driver.tear_down_filter()

        self.assert_driver_was_locked_once()
        self.mock_reset.assert_called_once_with()

    def test_get_periodic_sync_task(self):
        sync_mock = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'sync')).mock
        self.driver.get_periodic_sync_task()
        self.mock_periodic.assert_called_once_with(spacing=15, enabled=True)
        self.mock_periodic.return_value.call_args[0][0]()
        sync_mock.assert_called_once_with(self.mock_get_client.return_value)

    def test_get_periodic_sync_task_invalid_state(self):
        sync_mock = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'sync')).mock
        sync_mock.side_effect = pxe_filter.InvalidFilterDriverState('Oops!')

        self.driver.get_periodic_sync_task()
        self.mock_periodic.assert_called_once_with(spacing=15, enabled=True)
        self.assertRaisesRegex(periodics.NeverAgain, 'Oops!',
                               self.mock_periodic.return_value.call_args[0][0])

    def test_get_periodic_sync_task_custom_error(self):
        class MyError(Exception):
            pass

        sync_mock = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'sync')).mock
        sync_mock.side_effect = MyError('Oops!')

        self.driver.get_periodic_sync_task()
        self.mock_periodic.assert_called_once_with(spacing=15, enabled=True)
        self.assertRaisesRegex(
            MyError, 'Oops!', self.mock_periodic.return_value.call_args[0][0])

    def test_get_periodic_sync_task_disabled(self):
        CONF.set_override('sync_period', 0, 'pxe_filter')
        self.driver.get_periodic_sync_task()
        self.mock_periodic.assert_called_once_with(spacing=float('inf'),
                                                   enabled=False)

    def test_get_periodic_sync_task_custom_spacing(self):
        CONF.set_override('sync_period', 4224, 'pxe_filter')
        self.driver.get_periodic_sync_task()
        self.mock_periodic.assert_called_once_with(spacing=4224, enabled=True)


class TestDriverReset(BaseFilterBaseTest):
    def setUp(self):
        super(TestDriverReset, self).setUp()
        self.mock_fsm = self.useFixture(
            fixtures.MockPatchObject(self.driver, 'fsm')).mock

    def test_reset(self):
        self.driver.reset()

        self.assert_driver_was_not_locked()
        self.mock_fsm.process_event.assert_called_once_with(
            pxe_filter.Events.reset)


class TestDriver(test_base.BaseTest):
    def setUp(self):
        super(TestDriver, self).setUp()
        self.mock_driver = mock.Mock(spec=interface.FilterDriver)
        self.mock__driver_manager = self.useFixture(
            fixtures.MockPatchObject(pxe_filter, '_driver_manager')).mock
        self.mock__driver_manager.return_value.driver = self.mock_driver

    def test_driver(self):
        ret = pxe_filter.driver()

        self.assertIs(self.mock_driver, ret)
        self.mock__driver_manager.assert_called_once_with()


class TestIBMapping(test_base.BaseTest):
    def setUp(self):
        super(TestIBMapping, self).setUp()
        CONF.set_override('ethoib_interfaces', ['eth0'], 'iptables')
        self.ib_data = (
            'EMAC=02:00:02:97:00:01 IMAC=97:fe:80:00:00:00:00:00:00:7c:fe:90:'
            '03:00:29:26:52\n'
            'EMAC=02:00:00:61:00:02 IMAC=61:fe:80:00:00:00:00:00:00:7c:fe:90:'
            '03:00:29:24:4f\n'
        )
        self.client_id = ('ff:00:00:00:00:00:02:00:00:02:c9:00:7c:fe:90:03:00:'
                          '29:24:4f')
        self.ib_address = '7c:fe:90:29:24:4f'
        self.ib_port = mock.Mock(address=self.ib_address,
                                 extra={'client-id': self.client_id},
                                 spec=['address', 'extra'])
        self.port = mock.Mock(address='aa:bb:cc:dd:ee:ff',
                              extra={}, spec=['address', 'extra'])
        self.ports = [self.ib_port, self.port]
        self.expected_rmac = '02:00:00:61:00:02'
        self.fileobj = mock.mock_open(read_data=self.ib_data)

    def test_matching_ib(self):
        with mock.patch('builtins.open', self.fileobj,
                        create=True) as mock_open:
            pxe_filter._ib_mac_to_rmac_mapping(self.ports)

        self.assertEqual(self.expected_rmac, self.ib_port.address)
        self.assertEqual(self.ports, [self.ib_port, self.port])
        mock_open.assert_called_once_with('/sys/class/net/eth0/eth/neighs',
                                          'r')

    def test_ib_not_match(self):
        self.ports[0].extra['client-id'] = 'foo'
        with mock.patch('builtins.open', self.fileobj,
                        create=True) as mock_open:
            pxe_filter._ib_mac_to_rmac_mapping(self.ports)

        self.assertEqual(self.ib_address, self.ib_port.address)
        self.assertEqual(self.ports, [self.ib_port, self.port])
        mock_open.assert_called_once_with('/sys/class/net/eth0/eth/neighs',
                                          'r')

    def test_open_no_such_file(self):
        with mock.patch('builtins.open',
                        side_effect=IOError(), autospec=True) as mock_open:
            pxe_filter._ib_mac_to_rmac_mapping(self.ports)

        self.assertEqual(self.ib_address, self.ib_port.address)
        self.assertEqual(self.ports, [self.ib_port, self.port])
        mock_open.assert_called_once_with('/sys/class/net/eth0/eth/neighs',
                                          'r')

    def test_no_interfaces(self):
        CONF.set_override('ethoib_interfaces', [], 'iptables')
        with mock.patch('builtins.open', self.fileobj,
                        create=True) as mock_open:
            pxe_filter._ib_mac_to_rmac_mapping(self.ports)

        self.assertEqual(self.ib_address, self.ib_port.address)
        self.assertEqual(self.ports, [self.ib_port, self.port])
        mock_open.assert_not_called()


class TestGetInactiveMacs(test_base.BaseTest):
    def setUp(self):
        super(TestGetInactiveMacs, self).setUp()
        self.mock__ib_mac_to_rmac_mapping = self.useFixture(
            fixtures.MockPatchObject(pxe_filter,
                                     '_ib_mac_to_rmac_mapping')).mock
        self.mock_active_macs = self.useFixture(
            fixtures.MockPatchObject(node_cache, 'active_macs')).mock
        self.mock_ironic = mock.Mock()

    def test_inactive_port(self):
        mock_ports_list = [
            mock.Mock(address='foo'),
            mock.Mock(address='bar'),
        ]
        self.mock_ironic.ports.return_value = mock_ports_list
        self.mock_active_macs.return_value = {'foo'}

        ports = pxe_filter.get_inactive_macs(self.mock_ironic)
        self.assertEqual({'bar'}, ports)
        self.mock_ironic.ports.assert_called_once_with(
            limit=None, fields=['address', 'extra'])
        self.mock__ib_mac_to_rmac_mapping.assert_called_once_with(
            [mock_ports_list[1]])

    @mock.patch('time.sleep', lambda _x: None)
    def test_retry_on_port_list_failure(self):
        mock_ports_list = [
            mock.Mock(address='foo'),
            mock.Mock(address='bar'),
        ]
        self.mock_ironic.ports.side_effect = [
            os_exc.SDKException('boom'),
            mock_ports_list
        ]
        self.mock_active_macs.return_value = {'foo'}

        ports = pxe_filter.get_inactive_macs(self.mock_ironic)
        self.assertEqual({'bar'}, ports)
        self.mock_ironic.ports.assert_called_with(
            limit=None, fields=['address', 'extra'])
        self.mock__ib_mac_to_rmac_mapping.assert_called_once_with(
            [mock_ports_list[1]])


class TestGetActiveMacs(test_base.BaseTest):
    def setUp(self):
        super(TestGetActiveMacs, self).setUp()
        self.mock__ib_mac_to_rmac_mapping = self.useFixture(
            fixtures.MockPatchObject(pxe_filter,
                                     '_ib_mac_to_rmac_mapping')).mock
        self.mock_active_macs = self.useFixture(
            fixtures.MockPatchObject(node_cache, 'active_macs')).mock
        self.mock_ironic = mock.Mock()

    def test_active_port(self):
        mock_ports_list = [
            mock.Mock(address='foo'),
            mock.Mock(address='bar'),
        ]
        self.mock_ironic.ports.return_value = mock_ports_list
        self.mock_active_macs.return_value = {'foo'}

        ports = pxe_filter.get_active_macs(self.mock_ironic)
        self.assertEqual({'foo'}, ports)
        self.mock_ironic.ports.assert_called_once_with(
            limit=None, fields=['address', 'extra'])
        self.mock__ib_mac_to_rmac_mapping.assert_called_once_with(
            [mock_ports_list[0]])

    @mock.patch('time.sleep', lambda _x: None)
    def test_retry_on_port_list_failure(self):
        mock_ports_list = [
            mock.Mock(address='foo'),
            mock.Mock(address='bar'),
        ]
        self.mock_ironic.ports.side_effect = [
            os_exc.SDKException('boom'),
            mock_ports_list
        ]
        self.mock_active_macs.return_value = {'foo'}

        ports = pxe_filter.get_active_macs(self.mock_ironic)
        self.assertEqual({'foo'}, ports)
        self.mock_ironic.ports.assert_called_with(
            limit=None, fields=['address', 'extra'])
        self.mock__ib_mac_to_rmac_mapping.assert_called_once_with(
            [mock_ports_list[0]])


class TestGetIronicMacs(test_base.BaseTest):
    def setUp(self):
        super(TestGetIronicMacs, self).setUp()
        self.mock__ib_mac_to_rmac_mapping = self.useFixture(
            fixtures.MockPatchObject(pxe_filter,
                                     '_ib_mac_to_rmac_mapping')).mock
        self.mock_ironic = mock.Mock()

    def test_active_port(self):
        mock_ports_list = [
            mock.Mock(address='foo'),
            mock.Mock(address='bar'),
        ]
        self.mock_ironic.ports.return_value = mock_ports_list

        ports = pxe_filter.get_ironic_macs(self.mock_ironic)
        self.assertEqual({'foo', 'bar'}, ports)
        self.mock_ironic.ports.assert_called_once_with(
            limit=None, fields=['address', 'extra'])
        self.mock__ib_mac_to_rmac_mapping.assert_called_once_with(
            mock_ports_list)

    @mock.patch('time.sleep', lambda _x: None)
    def test_retry_on_port_list_failure(self):
        mock_ports_list = [
            mock.Mock(address='foo'),
            mock.Mock(address='bar'),
        ]
        self.mock_ironic.ports.side_effect = [
            os_exc.SDKException('boom'),
            mock_ports_list
        ]

        ports = pxe_filter.get_ironic_macs(self.mock_ironic)
        self.assertEqual({'foo', 'bar'}, ports)
        self.mock_ironic.ports.assert_called_with(
            limit=None, fields=['address', 'extra'])
        self.mock__ib_mac_to_rmac_mapping.assert_called_once_with(
            mock_ports_list)
