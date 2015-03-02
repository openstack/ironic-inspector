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


class BaseTest(test_base.NodeTest):
    def setUp(self):
        super(BaseTest, self).setUp()
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
        self.cached_node = mock.Mock(uuid=self.uuid, options={})

    def _prepare(self, client_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        return cli


@mock.patch.object(eventlet.greenthread, 'sleep', lambda _: None)
@mock.patch.object(eventlet.greenthread, 'spawn_n',
                   lambda f, *a, **kw: f(*a, **kw) and None)
@mock.patch.object(firewall, 'update_filters', autospec=True)
@mock.patch.object(node_cache, 'add_node', autospec=True)
@mock.patch.object(utils, 'get_client', autospec=True)
class TestIntrospect(BaseTest):
    def test_ok(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)
        cli.node.validate.assert_called_once_with(self.uuid)
        cli.node.list_ports.assert_called_once_with(self.uuid, limit=0)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address)
        self.cached_node.add_attribute.assert_called_once_with('mac',
                                                               self.macs)
        filters_mock.assert_called_with(cli)
        cli.node.set_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                         'reboot')
        add_mock.return_value.set_option.assert_called_once_with(
            'new_ipmi_credentials', None)

    def test_ok_ilo_and_drac(self, client_mock, add_mock, filters_mock):
        self._prepare(client_mock)
        add_mock.return_value = self.cached_node

        for name in ('ilo_address', 'drac_host'):
            self.node.driver_info = {name: self.bmc_address}
            introspect.introspect(self.node.uuid)

        add_mock.assert_called_with(self.uuid,
                                    bmc_address=self.bmc_address)

    def test_retries(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        cli.node.validate.side_effect = [exceptions.Conflict,
                                         mock.Mock(power={'result': True})]
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
                                         bmc_address=self.bmc_address)
        filters_mock.assert_called_with(cli)
        cli.node.set_boot_device.assert_called_with(self.uuid,
                                                    'pxe',
                                                    persistent=False)
        cli.node.set_power_state.assert_called_with(self.uuid,
                                                    'reboot')

    def test_power_failure(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        cli.node.set_boot_device.side_effect = exceptions.BadRequest()
        cli.node.set_power_state.side_effect = exceptions.BadRequest()
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address)
        cli.node.set_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                         'reboot')
        add_mock.return_value.finished.assert_called_once_with(
            error=mock.ANY)

    def test_unexpected_error(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        add_mock.return_value = self.cached_node
        filters_mock.side_effect = RuntimeError()

        introspect.introspect(self.node.uuid)

        cli.node.get.assert_called_once_with(self.uuid)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address)
        self.assertFalse(cli.node.set_boot_device.called)
        add_mock.return_value.finished.assert_called_once_with(
            error=mock.ANY)

    def test_juno_compat(self, client_mock, add_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.return_value = self.node_compat
        cli.node.validate.return_value = mock.Mock(power={'result': True})
        cli.node.list_ports.return_value = self.ports
        add_mock.return_value = mock.Mock(uuid=self.node_compat.uuid,
                                          options={})

        introspect.introspect(self.node_compat.uuid)

        cli.node.get.assert_called_once_with(self.node_compat.uuid)
        cli.node.validate.assert_called_once_with(self.node_compat.uuid)
        cli.node.list_ports.assert_called_once_with(self.node_compat.uuid,
                                                    limit=0)

        cli.node.update.assert_called_once_with(self.node_compat.uuid,
                                                self.patch)
        add_mock.assert_called_once_with(self.node_compat.uuid,
                                         bmc_address=None)
        add_mock.return_value.add_attribute.assert_called_once_with('mac',
                                                                    self.macs)
        filters_mock.assert_called_with(cli)
        cli.node.set_boot_device.assert_called_once_with(self.node_compat.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.node_compat.uuid,
                                                         'reboot')

    def test_no_macs(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        cli.node.list_ports.return_value = []
        add_mock.return_value = self.cached_node

        introspect.introspect(self.node.uuid)

        cli.node.list_ports.assert_called_once_with(self.uuid, limit=0)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address)
        self.assertFalse(self.cached_node.add_attribute.called)
        self.assertFalse(filters_mock.called)
        cli.node.set_boot_device.assert_called_once_with(self.uuid,
                                                         'pxe',
                                                         persistent=False)
        cli.node.set_power_state.assert_called_once_with(self.uuid,
                                                         'reboot')

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
            'node %s with provision state "active"' % self.uuid,
            introspect.introspect, self.uuid)

        self.assertEqual(0, cli.node.list_ports.call_count)
        self.assertEqual(0, filters_mock.call_count)
        self.assertEqual(0, cli.node.set_power_state.call_count)
        self.assertEqual(0, cli.node.update.call_count)
        self.assertFalse(add_mock.called)


@mock.patch.object(eventlet.greenthread, 'spawn_n',
                   lambda f, *a, **kw: f(*a, **kw) and None)
@mock.patch.object(firewall, 'update_filters', autospec=True)
@mock.patch.object(node_cache, 'add_node', autospec=True)
@mock.patch.object(utils, 'get_client', autospec=True)
class TestSetIpmiCredentials(BaseTest):
    def setUp(self):
        super(TestSetIpmiCredentials, self).setUp()
        conf.CONF.set('discoverd', 'enable_setting_ipmi_credentials', 'true')
        self.new_creds = ('user', 'password')
        self.cached_node.options['new_ipmi_credentials'] = self.new_creds
        self.node.maintenance = True

    def test_ok(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        add_mock.return_value = self.cached_node

        introspect.introspect(self.uuid, new_ipmi_credentials=self.new_creds)

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address)
        filters_mock.assert_called_with(cli)
        self.assertFalse(cli.node.validate.called)
        self.assertFalse(cli.node.set_boot_device.called)
        self.assertFalse(cli.node.set_power_state.called)
        add_mock.return_value.set_option.assert_called_once_with(
            'new_ipmi_credentials', self.new_creds)

    def test_disabled(self, client_mock, add_mock, filters_mock):
        conf.CONF.set('discoverd', 'enable_setting_ipmi_credentials', 'false')
        self._prepare(client_mock)

        self.assertRaisesRegexp(utils.Error, 'disabled',
                                introspect.introspect, self.uuid,
                                new_ipmi_credentials=self.new_creds)

    def test_no_username(self, client_mock, add_mock, filters_mock):
        self._prepare(client_mock)

        self.assertRaises(utils.Error, introspect.introspect, self.uuid,
                          new_ipmi_credentials=(None, 'password'))

    def test_default_username(self, client_mock, add_mock, filters_mock):
        cli = self._prepare(client_mock)
        add_mock.return_value = self.cached_node
        self.node.driver_info['ipmi_username'] = self.new_creds[0]

        introspect.introspect(self.uuid,
                              new_ipmi_credentials=(None, self.new_creds[1]))

        cli.node.update.assert_called_once_with(self.uuid, self.patch)
        add_mock.assert_called_once_with(self.uuid,
                                         bmc_address=self.bmc_address)
        filters_mock.assert_called_with(cli)
        self.assertFalse(cli.node.validate.called)
        self.assertFalse(cli.node.set_boot_device.called)
        self.assertFalse(cli.node.set_power_state.called)
        add_mock.return_value.set_option.assert_called_once_with(
            'new_ipmi_credentials', self.new_creds)

    def test_wrong_letters(self, client_mock, add_mock, filters_mock):
        self.new_creds = ('user', 'p ssw@rd')
        self._prepare(client_mock)

        self.assertRaises(utils.Error, introspect.introspect, self.uuid,
                          new_ipmi_credentials=self.new_creds)

    def test_too_long(self, client_mock, add_mock, filters_mock):
        self.new_creds = ('user', 'password' * 100)
        self._prepare(client_mock)

        self.assertRaises(utils.Error, introspect.introspect, self.uuid,
                          new_ipmi_credentials=self.new_creds)

    def test_require_maintenance(self, client_mock, add_mock, filters_mock):
        self.node.maintenance = False
        self._prepare(client_mock)

        self.assertRaises(utils.Error, introspect.introspect, self.uuid,
                          new_ipmi_credentials=self.new_creds)
