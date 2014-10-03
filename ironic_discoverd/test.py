import unittest

from ironicclient import exceptions
from mock import patch, Mock, ANY

from ironic_discoverd import discoverd


# FIXME(dtantsur): this test suite is far from being complete
@patch.object(discoverd.Firewall, 'update_filters')
@patch.object(discoverd, 'get_client')
class TestProcess(unittest.TestCase):
    def setUp(self):
        self.node = Mock(driver_info={},
                         maintenance=True,
                         properties={'cpu_arch': 'i386', 'local_gb': 40},
                         uuid='uuid')
        self.patch = [
            {'op': 'add', 'path': '/extra/newly_discovered', 'value': 'true'},
            {'op': 'add', 'path': '/properties/cpus', 'value': '2'},
            {'op': 'add', 'path': '/properties/memory_mb', 'value': '1024'},
        ]
        self.data = {
            'cpus': 2,
            'cpu_arch': 'x86_64',
            'memory_mb': 1024,
            'local_gb': 20,
            'macs': ['11:22:33:44:55:66', 'broken', '', '66:55:44:33:22:11'],
        }
        discoverd.Firewall.MACS_DISCOVERY = set(['11:22:33:44:55:66',
                                                 '66:55:44:33:22:11'])

    def test_bmc(self, client_mock, filters_mock):
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
        self.assertEqual(set(), discoverd.Firewall.MACS_DISCOVERY)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')

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
        self.assertEqual(set(), discoverd.Firewall.MACS_DISCOVERY)
        cli.node.set_power_state.assert_called_once_with(self.node.uuid, 'off')


@patch.object(discoverd.Firewall, 'update_filters')
@patch.object(discoverd, 'get_client')
class TestStart(unittest.TestCase):
    def setUp(self):
        self.node1 = Mock(driver='pxe_ssh',
                          maintenance=True,
                          uuid='uuid1')
        self.node2 = Mock(driver='pxe_ipmitool',
                          maintenance=True,
                          uuid='uuid2')
        discoverd.Firewall.MACS_DISCOVERY = set()

    def test(self, client_mock, filters_mock):
        cli = client_mock.return_value
        cli.node.get.side_effect = [
            exceptions.NotFound(),
            self.node1,
            Mock(maintenance=False),
            exceptions.Conflict(),
            self.node2,
        ]
        cli.node.list_ports.return_value = [Mock(address='1'),
                                            Mock(address='2')]

        discoverd.start(['uuid%d' % i for i in range(5)])

        self.assertEqual(5, cli.node.get.call_count)
        cli.node.list_ports.assert_called_once_with('uuid1', limit=0)
        filters_mock.assert_called_once_with(cli)
        self.assertEqual(set(['1', '2']), discoverd.Firewall.MACS_DISCOVERY)
        self.assertEqual(2, cli.node.set_power_state.call_count)
        cli.node.set_power_state.assert_called_with(ANY, 'on')
