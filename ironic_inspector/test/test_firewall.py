# Copyright 2015 NEC Corporation
# All Rights Reserved.
#
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

import subprocess

import mock
from oslo_config import cfg

from ironic_inspector import firewall
from ironic_inspector import node_cache
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


CONF = cfg.CONF


@mock.patch.object(firewall, '_iptables')
@mock.patch.object(utils, 'get_client')
@mock.patch.object(subprocess, 'check_call')
class TestFirewall(test_base.NodeTest):
    def test_update_filters_without_manage_firewall(self, mock_call,
                                                    mock_get_client,
                                                    mock_iptables):
        CONF.set_override('manage_firewall', False, 'firewall')
        firewall.update_filters()
        self.assertEqual(0, mock_iptables.call_count)

    def test_init_args(self, mock_call, mock_get_client, mock_iptables):
        rootwrap_path = '/some/fake/path'
        CONF.set_override('rootwrap_config', rootwrap_path)
        firewall.init()
        init_expected_args = [
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport', '67',
             '-j', CONF.firewall.firewall_chain),
            ('-F', CONF.firewall.firewall_chain),
            ('-X', CONF.firewall.firewall_chain),
            ('-N', CONF.firewall.firewall_chain)]

        call_args_list = mock_iptables.call_args_list

        for (args, call) in zip(init_expected_args, call_args_list):
            self.assertEqual(args, call[0])

        expected = ('sudo', 'ironic-inspector-rootwrap', rootwrap_path,
                    'iptables', '-w')
        self.assertEqual(expected, firewall.BASE_COMMAND)

    def test_init_args_old_iptables(self, mock_call, mock_get_client,
                                    mock_iptables):
        rootwrap_path = '/some/fake/path'
        CONF.set_override('rootwrap_config', rootwrap_path)
        mock_call.side_effect = subprocess.CalledProcessError(2, '')
        firewall.init()
        init_expected_args = [
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport', '67',
             '-j', CONF.firewall.firewall_chain),
            ('-F', CONF.firewall.firewall_chain),
            ('-X', CONF.firewall.firewall_chain),
            ('-N', CONF.firewall.firewall_chain)]

        call_args_list = mock_iptables.call_args_list

        for (args, call) in zip(init_expected_args, call_args_list):
            self.assertEqual(args, call[0])

        expected = ('sudo', 'ironic-inspector-rootwrap', rootwrap_path,
                    'iptables',)
        self.assertEqual(expected, firewall.BASE_COMMAND)

    def test_init_kwargs(self, mock_call, mock_get_client, mock_iptables):
        firewall.init()
        init_expected_kwargs = [
            {'ignore': True},
            {'ignore': True},
            {'ignore': True}]

        call_args_list = mock_iptables.call_args_list

        for (kwargs, call) in zip(init_expected_kwargs, call_args_list):
            self.assertEqual(kwargs, call[1])

    def test_update_filters_args(self, mock_call, mock_get_client,
                                 mock_iptables):
        firewall.init()

        update_filters_expected_args = [
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', CONF.firewall.firewall_chain),
            ('-F', CONF.firewall.firewall_chain),
            ('-X', CONF.firewall.firewall_chain),
            ('-N', CONF.firewall.firewall_chain),
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', firewall.NEW_CHAIN),
            ('-F', firewall.NEW_CHAIN),
            ('-X', firewall.NEW_CHAIN),
            ('-N', firewall.NEW_CHAIN),
            ('-A', firewall.NEW_CHAIN, '-j', 'ACCEPT'),
            ('-I', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', firewall.NEW_CHAIN),
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', CONF.firewall.firewall_chain),
            ('-F', CONF.firewall.firewall_chain),
            ('-X', CONF.firewall.firewall_chain),
            ('-E', firewall.NEW_CHAIN, CONF.firewall.firewall_chain)
        ]

        firewall.update_filters()
        call_args_list = mock_iptables.call_args_list

        for (args, call) in zip(update_filters_expected_args,
                                call_args_list):
            self.assertEqual(args, call[0])

    def test_update_filters_kwargs(self, mock_call, mock_get_client,
                                   mock_iptables):
        firewall.init()

        update_filters_expected_kwargs = [
            {'ignore': True},
            {'ignore': True},
            {'ignore': True},
            {},
            {'ignore': True},
            {'ignore': True},
            {'ignore': True},
            {},
            {},
            {},
            {'ignore': True},
            {'ignore': True},
            {'ignore': True}
        ]

        firewall.update_filters()
        call_args_list = mock_iptables.call_args_list

        for (kwargs, call) in zip(update_filters_expected_kwargs,
                                  call_args_list):
            self.assertEqual(kwargs, call[1])

    def test_update_filters_with_blacklist(self, mock_call, mock_get_client,
                                           mock_iptables):
        active_macs = ['11:22:33:44:55:66', '66:55:44:33:22:11']
        inactive_mac = ['AA:BB:CC:DD:EE:FF']
        self.macs = active_macs + inactive_mac
        self.ports = [mock.Mock(address=m) for m in self.macs]
        mock_get_client.port.list.return_value = self.ports
        node_cache.add_node(self.node.uuid, mac=active_macs,
                            bmc_address='1.2.3.4', foo=None)
        firewall.init()

        update_filters_expected_args = [
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', CONF.firewall.firewall_chain),
            ('-F', CONF.firewall.firewall_chain),
            ('-X', CONF.firewall.firewall_chain),
            ('-N', CONF.firewall.firewall_chain),
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', firewall.NEW_CHAIN),
            ('-F', firewall.NEW_CHAIN),
            ('-X', firewall.NEW_CHAIN),
            ('-N', firewall.NEW_CHAIN),
            # Blacklist
            ('-A', firewall.NEW_CHAIN, '-m', 'mac', '--mac-source',
             inactive_mac[0], '-j', 'DROP'),
            ('-A', firewall.NEW_CHAIN, '-j', 'ACCEPT'),
            ('-I', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', firewall.NEW_CHAIN),
            ('-D', 'INPUT', '-i', 'br-ctlplane', '-p', 'udp', '--dport',
             '67', '-j', CONF.firewall.firewall_chain),
            ('-F', CONF.firewall.firewall_chain),
            ('-X', CONF.firewall.firewall_chain),
            ('-E', firewall.NEW_CHAIN, CONF.firewall.firewall_chain)
        ]

        firewall.update_filters(mock_get_client)
        call_args_list = mock_iptables.call_args_list

        for (args, call) in zip(update_filters_expected_args,
                                call_args_list):
            self.assertEqual(args, call[0])
