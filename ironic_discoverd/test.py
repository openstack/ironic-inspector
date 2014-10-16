import unittest

from ironicclient import exceptions
from mock import patch, Mock, ANY

from ironic_discoverd import client
from ironic_discoverd import discoverd
from ironic_discoverd import firewall


def init_conf():
    discoverd.init_conf()
    discoverd.CONF.add_section('discoverd')


# FIXME(dtantsur): this test suite is far from being complete
@patch.object(firewall, 'update_filters', autospec=True)
@patch.object(discoverd, 'get_client', autospec=True)
class TestProcess(unittest.TestCase):
    def setUp(self):
        self.node = Mock(driver_info={},
                         properties={'cpu_arch': 'i386', 'local_gb': 40},
                         uuid='uuid',
                         extra={'on_discovery': 'true'})
        self.patch = [
            {'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
            {'op': 'remove', 'path': '/extra/on_discovery'},
            {'op': 'add', 'path': '/properties/cpus', 'value': '2'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '1024'},
        ]
        self.data = {
            'cpus': 2,
            'cpu_arch': 'x86_64',
            'memory_mb': 1024,
            'local_gb': 20,
            'interfaces': {
                'em1': {'mac': '11:22:33:44:55:66', 'ip': '1.2.3.4'},
                'em2': {'mac': 'broken', 'ip': '1.2.3.4'},
                'em3': {'mac': '', 'ip': '1.2.3.4'},
                'em4': {'mac': '66:55:44:33:22:11', 'ip': '1.2.3.4'},
                'em5': {'mac': '66:55:44:33:22:11'},
            }
        }
        self.macs = ['11:22:33:44:55:66', 'broken', '', '66:55:44:33:22:11']
        firewall.MACS_DISCOVERY = set(['11:22:33:44:55:66',
                                       '66:55:44:33:22:11'])
        init_conf()

    def _do_test_bmc(self, client_mock, filters_mock):
        self.node.driver_info['ipmi_address'] = '1.2.3.4'
        cli = client_mock.return_value
        cli.node.list.return_value = [
            Mock(driver_info={}),
            Mock(driver_info={'ipmi_address': '4.3.2.1'}),
            self.node,
            Mock(driver_info={'ipmi_address': '1.2.1.2'}),
        ]
        cli.port.create.side_effect = [None, exceptions.Conflict()]

        self.data['ipmi_address'] = '1.2.3.4'
        discoverd.process(self.data)

        self.assertTrue(cli.node.list.called)
        self.assertFalse(cli.port.get_by_address.called)
        cli.node.update.assert_called_once_with(self.node.uuid, self.patch)
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='11:22:33:44:55:66')
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='66:55:44:33:22:11')
        self.assertEqual(2, cli.port.create.call_count)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(), firewall.MACS_DISCOVERY)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')

    def test_bmc(self, client_mock, filters_mock):
        self._do_test_bmc(client_mock, filters_mock)

    def test_bmc_deprecated_macs(self, client_mock, filters_mock):
        del self.data['interfaces']
        self.data['macs'] = self.macs
        self._do_test_bmc(client_mock, filters_mock)

    def test_bmc_ports_for_inactive(self, client_mock, filters_mock):
        del self.data['interfaces']['em4']
        discoverd.CONF.set('discoverd', 'ports_for_inactive_interfaces',
                           'true')
        self._do_test_bmc(client_mock, filters_mock)

    def test_macs(self, client_mock, filters_mock):
        discoverd.ALLOW_SEARCH_BY_MAC = True
        cli = client_mock.return_value
        cli.port.get_by_address.side_effect = [
            exceptions.NotFound(), Mock(node_uuid=self.node.uuid)]
        cli.port.create.side_effect = [None, exceptions.Conflict()]
        cli.node.get.return_value = self.node

        discoverd.process(self.data)

        self.assertFalse(cli.node.list.called)
        cli.port.get_by_address.assert_any_call('11:22:33:44:55:66')
        cli.port.get_by_address.assert_any_call('66:55:44:33:22:11')
        cli.node.get.assert_called_once_with(self.node.uuid)
        cli.node.update.assert_called_once_with(self.node.uuid, self.patch)
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='11:22:33:44:55:66')
        cli.port.create.assert_any_call(node_uuid=self.node.uuid,
                                        address='66:55:44:33:22:11')
        self.assertEqual(2, cli.port.create.call_count)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(), firewall.MACS_DISCOVERY)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')


@patch.object(firewall, 'update_filters', autospec=True)
@patch.object(discoverd, 'get_client', autospec=True)
class TestDiscover(unittest.TestCase):
    def setUp(self):
        self.node1 = Mock(driver='pxe_ssh',
                          uuid='uuid1')
        self.node2 = Mock(driver='pxe_ipmitool',
                          uuid='uuid2')
        firewall.MACS_DISCOVERY = set()
        init_conf()

    def test(self, client_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            exceptions.NotFound(),
            self.node1,
            exceptions.Conflict(),
            self.node2,
        ]
        cli.node.list_ports.return_value = [Mock(address='1'),
                                            Mock(address='2')]

        discoverd.discover(['uuid%d' % i for i in range(4)])

        self.assertEqual(4, cli.node.get.call_count)
        cli.node.list_ports.assert_called_once_with('uuid1', limit=0)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(['1', '2']), firewall.MACS_DISCOVERY)
        self.assertEqual(2, cli.node.set_power_state.call_count)
        cli.node.set_power_state.assert_called_with(ANY, 'on')
        patch = [{'op': 'add', 'path': '/extra/on_discovery', 'value': 'true'}]
        cli.node.update.assert_any_call('uuid1', patch)
        cli.node.update.assert_any_call('uuid3', patch)
        self.assertEqual(2, cli.node.update.call_count)


@patch.object(client.requests, 'post', autospec=True)
class TestClient(unittest.TestCase):
    def test_client(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_client_full_url(self, mock_post):
        client.discover(['uuid1', 'uuid2'], base_url="http://host:port/v1/",
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://host:port/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )

    def test_client_default_url(self, mock_post):
        client.discover(['uuid1', 'uuid2'],
                        auth_token="token")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:5050/v1/discover",
            data='["uuid1", "uuid2"]',
            headers={'Content-Type': 'application/json',
                     'X-Auth-Token': 'token'}
        )


if __name__ == '__main__':
    unittest.main()
