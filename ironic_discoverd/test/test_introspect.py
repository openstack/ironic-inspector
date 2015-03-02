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

import eventlet
from ironicclient import exceptions
import mock

from ironic_discoverd import conf
from ironic_discoverd import firewall
from ironic_discoverd import introspect
from ironic_discoverd import node_cache
from ironic_discoverd.test import base as test_base
from ironic_discoverd import utils


@mock.patch.object(eventlet.greenthread, 'sleep', lambda _: None)
@mock.patch.object(eventlet.greenthread, 'spawn_n',
                   lambda f, *a, **kw: f(*a, **kw) and None)
@mock.patch.object(firewall, 'update_filters', autospec=True)
@mock.patch.object(node_cache, 'add_node', autospec=True)
@mock.patch.object(utils, 'get_client', autospec=True)
class TestIntrospect(test_base.NodeTest):
    def setUp(self):
        super(TestIntrospect, self).setUp()
        self.node.power_state = 'power off'
        self.node_compat = mock.Mock(driver='pxe_ssh',
                                     uuid='uuid_compat',
                                     driver_info={},
                                     maintenance=True,
                                     # allowed with maintenance=True
                                     power_state='power on',
                                     provision_state='foobar',
                                     extra={'on_discovery': True})
        self.ports = [mock.Mock(address=m) for m in self.macs]
        self.patch = [{'op': 'add', 'path': '/extra/on_discovery',
                       'value': 'true'}]
        self.cached_node = mock.Mock(uuid=self.uuid)

    def test_ok(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)
        cli.node.validate.assert_called_once_with(self.uuid)
        cli.node.list_ports.assert_called_once_with(self.uuid, limit=0)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address,
                                         mac=self.macs)
        filters_mock.assert_called_with(cli)
        cli.node.set_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                         'reboot')
        add_mock.return_value.set_option.assert_called_once_with(
            'setup_ipmi_credentials', False)

    def test_ok_ilo_and_drac(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        add_mock.return_value = self.cached_node

        for name in ('ilo_address', 'drac_host'):
            self.node.driver_info = {name: self.bmc_address}
            introspect.introspect(self.node.uuid)

        add_mock.assert_called_with(self.uuid,
                                    bmc_address=self.bmc_address,
                                    mac=self.macs)

    def test_retries(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.side_effect = [exceptions.Conflict,
                                         mock.Mock(power={'result': True})]
        cli.node.list_ports.return_value = self.ports
        cli.node.update.side_effect = [exceptions.Conflict,
                                       exceptions.Conflict,
                                       None]
        cli.node.set_boot_device.side_effect = [exceptions.Conflict,
                                                None]
        cli.node.set_power_state.side_effect = [exceptions.Conflict,
                                                None]
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)
        cli.node.validate.assert_called_with(self.uuid)
        cli.node.list_ports.assert_called_once_with(self.uuid, limit=0)

        cli.node.update.assert_called_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address,
                                         mac=self.macs)
        filters_mock.assert_called_with(cli)
        cli.node.set_boot_device.assert_called_with(self.uuid,
                                                    'pxe',
                                                    persistent=False)
        cli.node.set_power_state.assert_called_with(self.uuid,
                                                    'reboot')

    def test_power_failure(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        cli.node.set_boot_device.side_effect = exceptions.BadRequest()
        cli.node.set_power_state.side_effect = exceptions.BadRequest()
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address,
                                         mac=self.macs)
        cli.node.set_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                         'reboot')
        add_mock.return_value.finished.assert_called_once_with(
            error=mock.ANY)

    def test_unexpected_error(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        add_mock.return_value = self.cached_node
        filters_mock.side_effect = RuntimeError()

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address,
                                         mac=self.macs)
        self.assertFalse(cli.node.set_boot_device.called)
        add_mock.return_value.finished.assert_called_once_with(
            error=mock.ANY)

    def test_juno_compat(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node_compat
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        add_mock.return_value = mock.Mock(uuid=self.node_compat.uuid)

        introspect.introspect(self.node_compat.uuid)

        cli.node.get.assert_called_once_with(self.node_compat.uuid)
        cli.node.validate.assert_called_once_with(self.node_compat.uuid)
        cli.node.list_ports.assert_called_once_with(self.node_compat.uuid,
                                                    limit=0)

        cli.node.update.assert_called_once_with(self.node_compat.uuid,
                                                self.patch)
        add_mock.assert_called_once_with(self.node_compat.uuid,
                                         bmc_address=None,
                                         mac=self.macs)
        filters_mock.assert_called_with(cli)
        cli.node.set_boot_device.assert_called_once_with(self.node_compat.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.node_compat.uuid,
                                                         'reboot')

    def test_no_macs(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.list_ports.return_value = []
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.list_ports.assert_called_once_with(self.uuid, limit=0)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address,
                                         mac=[])
        self.assertFalse(filters_mock.called)
        cli.node.set_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                         'reboot')

    def test_setup_ipmi_credentials(self, client_mock, add_mock, filters_mock):
        conf.CONF.set('discoverd', 'enable_setting_ipmi_credentials', 'true')

        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.list_ports.return_value = self.ports
        cli.node.validate.side_effect = Exception()

        introspect.introspect(self.uuid, setup_ipmi_credentials=True)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address,
                                         mac=self.macs)
        filters_mock.assert_called_with(cli)
        self.assertFalse(cli.node.set_boot_device.called)
        self.assertFalse(cli.node.set_power_state.called)

    def test_setup_ipmi_credentials_disabled(self, client_mock, add_mock,
                                             filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.list_ports.return_value = []
        cli.node.validate.side_effect = Exception()

        self.assertRaisesRegexp(utils.Error, 'disabled',
                                introspect.introspect, self.uuid,
                                setup_ipmi_credentials=True)

    def test_failed_to_get_node(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = exceptions.NotFound()
        self.assertRaisesRegexp(utils.Error,
                                'Cannot find node',
                                introspect.introspect, self.uuid)

        cli.node.get.side_effect = exceptions.BadRequest()
        self.assertRaisesRegexp(utils.Error,
                                'Cannot get node',
                                introspect.introspect, self.uuid)

        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)

    def test_failed_to_validate_node(self, client_mock, add_mock,
                                     filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.return_value = mock.Mock(power={'result': False,
                                                          'reason': 'oops'})

        self.assertRaisesRegexp(
            utils.Error,
            'Failed validation of power interface for node',
            introspect.introspect, self.uuid)

        cli.node.validate.assert_called_once_with(self.uuid)
        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)

    def test_wrong_provision_state(self, client_mock, add_mock, filters_mock):
        self.node.provision_state = 'active'
        cli = client_mock.return_value
        cli.node.get.return_value = self.node

        self.assertRaisesRegexp(
            utils.Error,
            'node uuid with provision state "active"',
            introspect.introspect, self.uuid)

        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)
