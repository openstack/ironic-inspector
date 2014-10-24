import logging
import subprocess

from eventlet import semaphore


LOG = logging.getLogger("discoverd")
MACS_DISCOVERY = set()
NEW_CHAIN = 'discovery_temp'
CHAIN = 'discovery'
INTERFACE = None
LOCK = semaphore.BoundedSemaphore()


def _iptables(*args, **kwargs):
    cmd = ('iptables',) + args
    ignore = kwargs.pop('ignore', False)
    LOG.debug('Running iptables %s', args)
    kwargs['stderr'] = subprocess.STDOUT
    try:
        subprocess.check_output(cmd, **kwargs)
    except subprocess.CalledProcessError as exc:
        if ignore:
            LOG.debug('iptables %s failed (ignoring):\n%s', args,
                      exc.output)
        else:
            LOG.error('iptables %s failed:\n%s', args, exc.output)
            raise


def init(interface):
    global INTERFACE
    INTERFACE = interface

    _iptables('-D', 'INPUT', '-i', INTERFACE, '-p', 'udp',
              '--dport', '67', '-j', CHAIN,
              ignore=True)  # may be missing on first run
    _iptables('-F', CHAIN, ignore=True)
    _iptables('-X', CHAIN, ignore=True)
    # Code expects it to exist
    _iptables('-N', CHAIN)


def whitelist_macs(macs):
    with LOCK:
        MACS_DISCOVERY.update(macs)


def unwhitelist_macs(macs):
    with LOCK:
        MACS_DISCOVERY.difference_update(macs)


def update_filters(ironic):
    assert INTERFACE is not None
    with LOCK:
        macs_active = set(p.address for p in ironic.port.list(limit=0))
        to_blacklist = macs_active - MACS_DISCOVERY

        # Clean up a bit to accout for possible troubles on previous run
        _iptables('-F', NEW_CHAIN, ignore=True)
        _iptables('-X', NEW_CHAIN, ignore=True)
        _iptables('-N', CHAIN, ignore=True)
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
                  ignore=True)  # may be missing on first run
        _iptables('-F', CHAIN)
        _iptables('-X', CHAIN)
        _iptables('-E', NEW_CHAIN, CHAIN)
