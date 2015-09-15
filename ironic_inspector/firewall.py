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

import os
import subprocess

from eventlet import semaphore
from oslo_config import cfg
from oslo_log import log

from ironic_inspector.common.i18n import _LE, _LW
from ironic_inspector import node_cache
from ironic_inspector import utils


CONF = cfg.CONF
LOG = log.getLogger("ironic_inspector.firewall")
NEW_CHAIN = None
CHAIN = None
INTERFACE = None
LOCK = semaphore.BoundedSemaphore()
BASE_COMMAND = None


def _iptables(*args, **kwargs):
    # NOTE(dtantsur): -w flag makes it wait for xtables lock
    cmd = BASE_COMMAND + args
    ignore = kwargs.pop('ignore', False)
    LOG.debug('Running iptables %s', args)
    kwargs['stderr'] = subprocess.STDOUT
    try:
        subprocess.check_output(cmd, **kwargs)
    except subprocess.CalledProcessError as exc:
        if ignore:
            LOG.debug('ignoring failed iptables %s:\n%s', args, exc.output)
        else:
            LOG.error(_LE('iptables %(iptables)s failed:\n%(exc)s') %
                      {'iptables': args, 'exc': exc.output})
            raise


def init():
    """Initialize firewall management.

    Must be called one on start-up.
    """
    if not CONF.firewall.manage_firewall:
        return

    global INTERFACE, CHAIN, NEW_CHAIN, BASE_COMMAND
    INTERFACE = CONF.firewall.dnsmasq_interface
    CHAIN = CONF.firewall.firewall_chain
    NEW_CHAIN = CHAIN + '_temp'
    BASE_COMMAND = ('sudo', 'ironic-inspector-rootwrap',
                    CONF.rootwrap_config, 'iptables',)

    # -w flag makes iptables wait for xtables lock, but it's not supported
    # everywhere yet
    try:
        with open(os.devnull, 'wb') as null:
            subprocess.check_call(BASE_COMMAND + ('-w', '-h'),
                                  stderr=null, stdout=null)
    except subprocess.CalledProcessError:
        LOG.warn(_LW('iptables does not support -w flag, please update '
                     'it to at least version 1.4.21'))
    else:
        BASE_COMMAND += ('-w',)

    _clean_up(CHAIN)
    # Not really needed, but helps to validate that we have access to iptables
    _iptables('-N', CHAIN)


def _clean_up(chain):
    _iptables('-D', 'INPUT', '-i', INTERFACE, '-p', 'udp',
              '--dport', '67', '-j', chain,
              ignore=True)
    _iptables('-F', chain, ignore=True)
    _iptables('-X', chain, ignore=True)


def clean_up():
    """Clean up everything before exiting."""
    if not CONF.firewall.manage_firewall:
        return

    _clean_up(CHAIN)
    _clean_up(NEW_CHAIN)


def update_filters(ironic=None):
    """Update firewall filter rules for introspection.

    Gives access to PXE boot port for any machine, except for those,
    whose MAC is registered in Ironic and is not on introspection right now.

    This function is called from both introspection initialization code and
    from periodic task. This function is supposed to be resistant to unexpected
    iptables state.

    ``init()`` function must be called once before any call to this function.
    This function is using ``eventlet`` semaphore to serialize access from
    different green threads.

    Does nothing, if firewall management is disabled in configuration.

    :param ironic: Ironic client instance, optional.
    """
    if not CONF.firewall.manage_firewall:
        return

    assert INTERFACE is not None
    ironic = utils.get_client() if ironic is None else ironic

    with LOCK:
        macs_active = set(p.address for p in ironic.port.list(limit=0))
        to_blacklist = macs_active - node_cache.active_macs()
        LOG.debug('Blacklisting active MAC\'s %s', to_blacklist)

        # Clean up a bit to account for possible troubles on previous run
        _clean_up(NEW_CHAIN)
        # Operate on temporary chain
        _iptables('-N', NEW_CHAIN)
        # - Blacklist active macs, so that nova can boot them
        for mac in to_blacklist:
            _iptables('-A', NEW_CHAIN, '-m', 'mac',
                      '--mac-source', mac, '-j', 'DROP')
        # - Whitelist everything else
        _iptables('-A', NEW_CHAIN, '-j', 'ACCEPT')

        # Swap chains
        _iptables('-I', 'INPUT', '-i', INTERFACE, '-p', 'udp',
                  '--dport', '67', '-j', NEW_CHAIN)
        _iptables('-D', 'INPUT', '-i', INTERFACE, '-p', 'udp',
                  '--dport', '67', '-j', CHAIN,
                  ignore=True)
        _iptables('-F', CHAIN, ignore=True)
        _iptables('-X', CHAIN, ignore=True)
        _iptables('-E', NEW_CHAIN, CHAIN)
