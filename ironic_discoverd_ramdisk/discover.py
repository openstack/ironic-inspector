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

import base64
import json
import logging
import os
import subprocess
import tarfile
import tempfile

import netifaces
import requests


LOG = logging.getLogger('ironic-discoverd-ramdisk')


def try_call(*cmd, **kwargs):
    strip = kwargs.pop('strip', True)
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    try:
        p = subprocess.Popen(cmd, **kwargs)
        out, err = p.communicate()
    except EnvironmentError as exc:
        LOG.warn('command %s failed: %s', cmd, exc)
        return

    if p.returncode:
        LOG.warn('command %s returned failure status %d:\n%s', cmd,
                 p.returncode, err.strip())
    else:
        return out.strip() if strip else out


def try_shell(sh, **kwargs):
    strip = kwargs.pop('strip', True)
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    kwargs['shell'] = True

    p = subprocess.Popen([sh], **kwargs)
    out, err = p.communicate()
    if p.returncode:
        LOG.warn('shell script "%s" failed with code %d:\n%s', sh,
                 p.returncode, err.strip())
    else:
        return out.strip() if strip else out


class AccumulatedFailure(object):
    """Object accumulated failures without raising exception."""
    def __init__(self):
        self._failures = []

    def add(self, fail, *fmt):
        """Add failure with optional formatting."""
        if fmt:
            fail = fail % fmt
        LOG.error('%s', fail)
        self._failures.append(fail)

    def get_error(self):
        """Get error string or None."""
        if not self._failures:
            return

        msg = ('The following errors were encountered during '
               'hardware discovery:\n%s'
               % '\n'.join('* %s' % item for item in self._failures))
        return msg

    def __nonzero__(self):
        return bool(self._failures)

    __bool__ = __nonzero__

    def __repr__(self):  # pragma: no cover
        # This is for tests
        if self:
            return '<%s: %s>' % (self.__class__.__name__,
                                 ', '.join(self._failures))
        else:
            return '<%s: success>' % self.__class__.__name__


def discover_basic_properties(data, args):
    # These properties might not be present, we don't count it as failure
    data['boot_interface'] = args.bootif
    data['ipmi_address'] = try_shell(
        "ipmitool lan print | grep -e 'IP Address [^S]' | awk '{ print $4 }'")
    LOG.info('BMC IP address: %s', data['ipmi_address'])


def discover_network_interfaces(data, failures):
    data.setdefault('interfaces', {})
    for iface in netifaces.interfaces():
        if iface.startswith('lo'):
            LOG.info('ignoring local network interface %s', iface)
            continue

        LOG.debug('found network interface %s', iface)
        addrs = netifaces.ifaddresses(iface)

        try:
            mac = addrs[netifaces.AF_LINK][0]['addr']
        except (KeyError, IndexError):
            LOG.info('no link information for interface %s in %s',
                     iface, addrs)
            continue

        try:
            ip = addrs[netifaces.AF_INET][0]['addr']
        except (KeyError, IndexError):
            LOG.info('no IP address for interface %s', iface)
            ip = None

        data['interfaces'][iface] = {'mac': mac, 'ip': ip}

    if data['interfaces']:
        LOG.info('network interfaces: %s', data['interfaces'])
    else:
        failures.add('no network interfaces found')


def discover_scheduling_properties(data, failures):
    scripts = [
        ('cpus', "grep processor /proc/cpuinfo | wc -l"),
        ('cpu_arch', "lscpu | grep Architecture | awk '{ print $2 }'"),
        ('local_gb', "fdisk -l | grep Disk | awk '{print $5}' | head -n 1"),
    ]
    for key, script in scripts:
        data[key] = try_shell(script)
        LOG.info('value for "%s" field is %s', key, data[key])

    ram_info = try_shell(
        "dmidecode --type memory | grep Size | awk '{ print $2; }'")
    if ram_info:
        total_ram = 0
        for ram_record in ram_info.split('\n'):
            try:
                total_ram += int(ram_record)
            except ValueError:
                pass
        data['memory_mb'] = total_ram
        LOG.info('total RAM: %s MiB', total_ram)
    else:
        failures.add('failed to get RAM information')

    for key in ('cpus', 'local_gb', 'memory_mb'):
        try:
            data[key] = int(data[key])
        except (KeyError, ValueError, TypeError):
            failures.add('value for %s is missing or malformed: %s',
                         key, data.get(key))
            data[key] = None

    # FIXME(dtantsur): -1 is required to give Ironic some spacing for
    # partitioning and may be removed later
    if data['local_gb']:
        data['local_gb'] = data['local_gb'] / 1024 / 1024 / 1024 - 1
        if data['local_gb'] < 1:
            failures.add('local_gb is less than 1 GiB')
            data['local_gb'] = None


def discover_additional_properties(args, data, failures):
    hw_args = ('--benchmark', 'cpu', 'disk', 'mem') if args.benchmark else ()
    hw_json = try_call('hardware-detect', *hw_args)
    if hw_json:
        try:
            data['data'] = json.loads(hw_json)
        except ValueError:
            LOG.error('JSON value returned from hardware-detect cannot be '
                      'decoded:\n%s', hw_json)
            failures.add('unable to get extended hardware properties')
    else:
        failures.add('unable to get extended hardware properties')


def discover_block_devices(data):
    block_devices = try_shell(
        "lsblk -no TYPE,SERIAL | grep disk | awk '{print $2}'")
    if not block_devices:
        LOG.warn('unable to get block devices')
        return

    serials = [item for item in block_devices.split('\n') if item.strip()]
    data['block_devices'] = {'serials': serials}


def discover_hardware(args, data, failures):
    try_call('modprobe', 'ipmi_msghandler')
    try_call('modprobe', 'ipmi_devintf')
    try_call('modprobe', 'ipmi_si')

    discover_basic_properties(data, args)
    discover_network_interfaces(data, failures)
    discover_scheduling_properties(data, failures)
    if args.use_hardware_detect:
        discover_additional_properties(args, data, failures)
    discover_block_devices(data)


def call_discoverd(args, data, failures):
    data['error'] = failures.get_error()

    LOG.info('posting collected data to %s', args.callback_url)
    resp = requests.post(args.callback_url, data=json.dumps(data))
    if resp.status_code >= 400:
        LOG.error('discoverd error %d: %s',
                  resp.status_code,
                  resp.content.decode('utf-8'))
        resp.raise_for_status()
    return resp.json()


def collect_logs(args):
    files = {args.log_file} | set(args.system_log_file or ())
    with tempfile.TemporaryFile() as fp:
        with tarfile.open(fileobj=fp, mode='w:gz') as tar:
            for fname in files:
                if os.path.exists(fname):
                    tar.add(fname)
                else:
                    LOG.warn('Log file %s does not exist', fname)

        fp.seek(0)
        return base64.b64encode(fp.read())


def setup_ipmi_credentials(resp):
    user, password = resp['ipmi_username'], resp['ipmi_password']
    if try_call('ipmitool', 'user', 'set', 'name', '2', user) is None:
        raise RuntimeError('failed to set IPMI user name to %s', user)
    if try_call('ipmitool', 'user', 'set', 'password', '2', password) is None:
        raise RuntimeError('failed to set IPMI password')
    try_call('ipmitool', 'user', 'enable', '2')
    try_call('ipmitool', 'channel', 'setaccess', '1', '2',
             'link=on', 'ipmi=on', 'callin=on', 'privilege=4')


def fork_and_serve_logs(args):
    pass  # TODO(dtantsur): implement
