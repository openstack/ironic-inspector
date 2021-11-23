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

import contextlib

from keystoneauth1 import exceptions as ksa_exc
from openstack import exceptions as os_exc
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log

from ironic_inspector import node_cache
from ironic_inspector.pxe_filter import base as pxe_filter

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def _should_enable_dhcp():
    """Check whether we should enable DHCP at all.

    We won't even open our DHCP if no nodes are on introspection and
    node_not_found_hook is not set.
    """
    return (node_cache.introspection_active() or
            CONF.processing.node_not_found_hook is not None)


class IptablesFilter(pxe_filter.BaseFilter):
    """A PXE boot filtering interface implementation."""

    def __init__(self):
        super(IptablesFilter, self).__init__()
        self.denylist_cache = None
        self.allowlist_cache = None
        self.enabled = True
        self.interface = CONF.iptables.dnsmasq_interface
        self.chain = CONF.iptables.firewall_chain
        self.new_chain = self.chain + '_temp'

        # Determine arguments used for pxe filtering, we only support 4 and 6
        # at this time.
        if CONF.iptables.ip_version == '4':
            self._cmd_iptables = 'iptables'
            self._dhcp_port = '67'
        else:
            self._cmd_iptables = 'ip6tables'
            self._dhcp_port = '547'

        self.base_command = ('sudo', 'ironic-inspector-rootwrap',
                             CONF.rootwrap_config, self._cmd_iptables)

    def reset(self):
        self.enabled = True
        self.denylist_cache = None
        self.allowlist_cache = None
        for chain in (self.chain, self.new_chain):
            try:
                self._clean_up(chain)
            except Exception as e:
                LOG.exception('Encountered exception resetting filter: %s', e)
        super(IptablesFilter, self).reset()

    @pxe_filter.locked_driver_event(pxe_filter.Events.initialize)
    def init_filter(self):
        # -w flag makes iptables wait for xtables lock, but it's not supported
        # everywhere yet
        try:
            cmd = self.base_command + ('-w', '-h')
            processutils.execute(*cmd)
        except processutils.ProcessExecutionError:
            LOG.warning('iptables does not support -w flag, please update '
                        'it to at least version 1.4.21')
        else:
            self.base_command += ('-w',)

        self._clean_up(self.chain)
        # Not really needed, but helps to validate that we have access to
        # iptables
        self._iptables('-N', self.chain)
        LOG.debug('The iptables filter was initialized')

    @pxe_filter.locked_driver_event(pxe_filter.Events.sync)
    def sync(self, ironic):
        """Sync firewall filter rules for introspection.

        Gives access to PXE boot port for any machine, except for those, whose
        MAC is registered in Ironic and is not on introspection right now.

        This function is called from both introspection initialization code and
        from periodic task. This function is supposed to be resistant to
        unexpected iptables state.

        ``init()`` function must be called once before any call to this
        function. This function is using ``eventlet`` semaphore to serialize
        access from different green threads.

        :param ironic: an ironic client instance.
        :returns: nothing.
        """
        if not _should_enable_dhcp():
            self._disable_dhcp()
            return

        try:
            if CONF.pxe_filter.deny_unknown_macs:
                to_allow = pxe_filter.get_active_macs(ironic)
                to_deny = None
            else:
                to_deny = pxe_filter.get_inactive_macs(ironic)
                to_allow = None
        except (os_exc.SDKException, ksa_exc.ConnectFailure):
            LOG.exception(
                "Could not list ironic ports, iptables PXE filter can not "
                "be synced")
            return

        if to_deny == self.denylist_cache and to_allow == self.allowlist_cache:
            LOG.debug('Not updating iptables - no changes in MAC lists %s %s',
                      to_deny, to_allow)
            return

        if CONF.pxe_filter.deny_unknown_macs:
            LOG.debug('Adding MAC\'s %s to the allow list', to_allow)
        else:
            LOG.debug('Adding MAC\'s %s to the deny list', to_deny)
        with self._temporary_chain(self.new_chain, self.chain):
            # Force update on the next iteration if this attempt fails
            self.denylist_cache = None
            self.allowlist_cache = None
            # - Add active macs to allow list, so that they are introspected
            if CONF.pxe_filter.deny_unknown_macs:
                for mac in to_allow:
                    self._iptables('-A', self.new_chain, '-m', 'mac',
                                   '--mac-source', mac, '-j', 'ACCEPT')
            # - Add inactive macs to the deny list, so that nova can boot them
            if not CONF.pxe_filter.deny_unknown_macs:
                for mac in to_deny:
                    self._iptables('-A', self.new_chain, '-m', 'mac',
                                   '--mac-source', mac, '-j', 'DROP')
            # - Add everything else to the unknown list
            policy = 'DROP' if CONF.pxe_filter.deny_unknown_macs else 'ACCEPT'
            self._iptables('-A', self.new_chain, '-j', policy)

        # Cache result of successful iptables update
        self.enabled = True
        self.denylist_cache = to_deny
        self.allowlist_cache = to_allow
        LOG.debug('The iptables filter was synchronized')

    @contextlib.contextmanager
    def _temporary_chain(self, chain, main_chain):
        """Context manager to operate on a temporary chain."""
        # Clean up a bit to account for possible troubles on previous run
        self._clean_up(chain)
        self._iptables('-N', chain)

        yield

        # Swap chains
        self._iptables('-I', 'INPUT', '-i', self.interface, '-p', 'udp',
                       '--dport', self._dhcp_port, '-j', chain)
        self._iptables('-D', 'INPUT', '-i', self.interface, '-p', 'udp',
                       '--dport', self._dhcp_port, '-j', main_chain,
                       ignore=True)
        self._iptables('-F', main_chain, ignore=True)
        self._iptables('-X', main_chain, ignore=True)
        self._iptables('-E', chain, main_chain)

    def _iptables(self, *args, **kwargs):
        # NOTE(dtantsur): -w flag makes it wait for xtables lock
        cmd = self.base_command + args
        ignore = kwargs.pop('ignore', False)
        try:
            processutils.execute(*cmd)
        except processutils.ProcessExecutionError as exc:
            if ignore:
                LOG.debug('Ignoring failed iptables %(args)s: %(error)s',
                          {'args': args, 'error': exc})
            else:
                LOG.error('iptables %(iptables)s failed: %(error)s',
                          {'iptables': args, 'error': exc})
                raise

    def _clean_up(self, chain):
        self._iptables('-D', 'INPUT', '-i', self.interface, '-p', 'udp',
                       '--dport', self._dhcp_port, '-j', chain,
                       ignore=True)
        self._iptables('-F', chain, ignore=True)
        self._iptables('-X', chain, ignore=True)

    def _disable_dhcp(self):
        """Disable DHCP completely."""
        if not self.enabled:
            LOG.debug('DHCP is already disabled, not updating')
            return

        LOG.debug('No nodes on introspection and node_not_found_hook is '
                  'not set - disabling DHCP')
        self.denylist_cache = None
        with self._temporary_chain(self.new_chain, self.chain):
            # deny everything
            self._iptables('-A', self.new_chain, '-j', 'REJECT')
            self.enabled = False
