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

"""Standard set of plugins."""

import base64
import datetime
import os
import sys

import netaddr
from oslo_config import cfg
from oslo_utils import units
import six

from ironic_inspector.common.i18n import _, _LC, _LE, _LI, _LW
from ironic_inspector import conf
from ironic_inspector.plugins import base
from ironic_inspector import utils

CONF = cfg.CONF


LOG = utils.getProcessingLogger('ironic_inspector.plugins.standard')


class RootDiskSelectionHook(base.ProcessingHook):
    """Smarter root disk selection using Ironic root device hints.

    This hook must always go before SchedulerHook, otherwise root_disk field
    might not be updated.
    """

    def before_update(self, introspection_data, node_info, **kwargs):
        """Detect root disk from root device hints and IPA inventory."""
        hints = node_info.node().properties.get('root_device')
        if not hints:
            LOG.debug('Root device hints are not provided',
                      node_info=node_info, data=introspection_data)
            return

        inventory = introspection_data.get('inventory')
        if not inventory:
            raise utils.Error(
                _('Root device selection requires ironic-python-agent '
                  'as an inspection ramdisk'),
                node_info=node_info, data=introspection_data)

        disks = inventory.get('disks', [])
        if not disks:
            raise utils.Error(_('No disks found'),
                              node_info=node_info, data=introspection_data)

        for disk in disks:
            properties = disk.copy()
            # Root device hints are in GiB, data from IPA is in bytes
            properties['size'] //= units.Gi

            for name, value in hints.items():
                actual = properties.get(name)
                if actual != value:
                    LOG.debug('Disk %(disk)s does not satisfy hint '
                              '%(name)s=%(value)s, actual value is %(actual)s',
                              {'disk': disk.get('name'), 'name': name,
                               'value': value, 'actual': actual},
                              node_info=node_info, data=introspection_data)
                    break
            else:
                LOG.debug('Disk %(disk)s of size %(size)s satisfies '
                          'root device hints',
                          {'disk': disk.get('name'), 'size': disk['size']},
                          node_info=node_info, data=introspection_data)
                introspection_data['root_disk'] = disk
                return

        raise utils.Error(_('No disks satisfied root device hints'),
                          node_info=node_info, data=introspection_data)


class SchedulerHook(base.ProcessingHook):
    """Nova scheduler required properties."""

    KEYS = ('cpus', 'cpu_arch', 'memory_mb', 'local_gb')

    def before_update(self, introspection_data, node_info, **kwargs):
        """Update node with scheduler properties."""
        inventory = introspection_data.get('inventory')
        errors = []

        root_disk = introspection_data.get('root_disk')
        if root_disk:
            introspection_data['local_gb'] = root_disk['size'] // units.Gi
            if CONF.processing.disk_partitioning_spacing:
                introspection_data['local_gb'] -= 1
        elif inventory:
            errors.append(_('root disk is not supplied by the ramdisk and '
                            'root_disk_selection hook is not enabled'))

        if inventory:
            try:
                introspection_data['cpus'] = int(inventory['cpu']['count'])
                introspection_data['cpu_arch'] = six.text_type(
                    inventory['cpu']['architecture'])
            except (KeyError, ValueError, TypeError):
                errors.append(_('malformed or missing CPU information: %s') %
                              inventory.get('cpu'))

            try:
                introspection_data['memory_mb'] = int(
                    inventory['memory']['physical_mb'])
            except (KeyError, ValueError, TypeError):
                errors.append(_('malformed or missing memory information: %s; '
                                'introspection requires physical memory size '
                                'from dmidecode') %
                              inventory.get('memory'))
        else:
            LOG.warning(_LW('No inventory provided: using old bash ramdisk '
                            'is deprecated, please switch to '
                            'ironic-python-agent'),
                        node_info=node_info, data=introspection_data)

            missing = [key for key in self.KEYS
                       if not introspection_data.get(key)]
            if missing:
                raise utils.Error(
                    _('The following required parameters are missing: %s') %
                    missing,
                    node_info=node_info, data=introspection_data)

        if errors:
            raise utils.Error(_('The following problems encountered: %s') %
                              '; '.join(errors),
                              node_info=node_info, data=introspection_data)

        LOG.info(_LI('Discovered data: CPUs: %(cpus)s %(cpu_arch)s, '
                     'memory %(memory_mb)s MiB, disk %(local_gb)s GiB'),
                 {key: introspection_data.get(key) for key in self.KEYS},
                 node_info=node_info, data=introspection_data)

        overwrite = CONF.processing.overwrite_existing
        properties = {key: str(introspection_data[key])
                      for key in self.KEYS if overwrite or
                      not node_info.node().properties.get(key)}
        node_info.update_properties(**properties)


class ValidateInterfacesHook(base.ProcessingHook):
    """Hook to validate network interfaces."""

    def __init__(self):
        if CONF.processing.add_ports not in conf.VALID_ADD_PORTS_VALUES:
            LOG.critical(_LC('Accepted values for [processing]add_ports are '
                             '%(valid)s, got %(actual)s'),
                         {'valid': conf.VALID_ADD_PORTS_VALUES,
                          'actual': CONF.processing.add_ports})
            sys.exit(1)

        if CONF.processing.keep_ports not in conf.VALID_KEEP_PORTS_VALUES:
            LOG.critical(_LC('Accepted values for [processing]keep_ports are '
                             '%(valid)s, got %(actual)s'),
                         {'valid': conf.VALID_KEEP_PORTS_VALUES,
                          'actual': CONF.processing.keep_ports})
            sys.exit(1)

    def _get_interfaces(self, data=None):
        """Convert inventory to a dict with interfaces.

        :return: dict interface name -> dict with keys 'mac' and 'ip'
        """
        result = {}
        inventory = data.get('inventory', {})

        if inventory:
            for iface in inventory.get('interfaces', ()):
                name = iface.get('name')
                mac = iface.get('mac_address')
                ip = iface.get('ipv4_address')

                if not name:
                    LOG.error(_LE('Malformed interface record: %s'),
                              iface, data=data)
                    continue

                LOG.debug('Found interface %(name)s with MAC "%(mac)s" and '
                          'IP address "%(ip)s"',
                          {'name': name, 'mac': mac, 'ip': ip}, data=data)
                result[name] = {'ip': ip, 'mac': mac}
        else:
            LOG.warning(_LW('No inventory provided: using old bash ramdisk '
                            'is deprecated, please switch to '
                            'ironic-python-agent'), data=data)
            result = data.get('interfaces')

        return result

    def _validate_interfaces(self, interfaces, data=None):
        """Validate interfaces on correctness and suitability.

        :return: dict interface name -> dict with keys 'mac' and 'ip'
        """
        if not interfaces:
            raise utils.Error(_('No interfaces supplied by the ramdisk'),
                              data=data)

        pxe_mac = utils.get_pxe_mac(data)
        if not pxe_mac and CONF.processing.add_ports == 'pxe':
            LOG.warning(_LW('No boot interface provided in the introspection '
                            'data, will add all ports with IP addresses'))

        result = {}

        for name, iface in interfaces.items():
            mac = iface.get('mac')
            ip = iface.get('ip')

            if not mac:
                LOG.debug('Skipping interface %s without link information',
                          name, data=data)
                continue

            if not utils.is_valid_mac(mac):
                LOG.warning(_LW('MAC %(mac)s for interface %(name)s is not '
                                'valid, skipping'),
                            {'mac': mac, 'name': name},
                            data=data)
                continue

            mac = mac.lower()

            if name == 'lo' or (ip and netaddr.IPAddress(ip).is_loopback()):
                LOG.debug('Skipping local interface %s', name, data=data)
                continue

            if (CONF.processing.add_ports == 'pxe' and pxe_mac
                    and mac != pxe_mac):
                LOG.debug('Skipping interface %s as it was not PXE booting',
                          name, data=data)
                continue
            elif CONF.processing.add_ports != 'all' and not ip:
                LOG.debug('Skipping interface %s as it did not have '
                          'an IP address assigned during the ramdisk run',
                          name, data=data)
                continue

            result[name] = {'ip': ip, 'mac': mac.lower()}

        if not result:
            raise utils.Error(_('No suitable interfaces found in %s') %
                              interfaces, data=data)
        return result

    def before_processing(self, introspection_data, **kwargs):
        """Validate information about network interfaces."""

        bmc_address = utils.get_ipmi_address_from_data(introspection_data)
        if bmc_address:
            introspection_data['ipmi_address'] = bmc_address
        else:
            LOG.debug('No BMC address provided in introspection data, '
                      'assuming virtual environment', data=introspection_data)

        all_interfaces = self._get_interfaces(introspection_data)

        interfaces = self._validate_interfaces(all_interfaces,
                                               introspection_data)

        LOG.info(_LI('Using network interface(s): %s'),
                 ', '.join('%s %s' % (name, items)
                           for (name, items) in interfaces.items()),
                 data=introspection_data)

        introspection_data['all_interfaces'] = all_interfaces
        introspection_data['interfaces'] = interfaces
        valid_macs = [iface['mac'] for iface in interfaces.values()]
        introspection_data['macs'] = valid_macs

    def before_update(self, introspection_data, node_info, **kwargs):
        """Drop ports that are not present in the data."""
        if CONF.processing.keep_ports == 'present':
            expected_macs = {
                iface['mac']
                for iface in introspection_data['all_interfaces'].values()
            }
        elif CONF.processing.keep_ports == 'added':
            expected_macs = set(introspection_data['macs'])
        else:
            return

        # list is required as we modify underlying dict
        for port in list(node_info.ports().values()):
            if port.address not in expected_macs:
                LOG.info(_LI("Deleting port %(port)s as its MAC %(mac)s is "
                             "not in expected MAC list %(expected)s"),
                         {'port': port.uuid,
                          'mac': port.address,
                          'expected': list(sorted(expected_macs))},
                         node_info=node_info, data=introspection_data)
                node_info.delete_port(port)


class RamdiskErrorHook(base.ProcessingHook):
    """Hook to process error send from the ramdisk."""

    DATETIME_FORMAT = '%Y.%m.%d_%H.%M.%S_%f'

    def before_processing(self, introspection_data, **kwargs):
        error = introspection_data.get('error')
        logs = introspection_data.get('logs')

        if error or CONF.processing.always_store_ramdisk_logs:
            if logs:
                self._store_logs(logs, introspection_data)
            else:
                LOG.debug('No logs received from the ramdisk',
                          data=introspection_data)

        if error:
            raise utils.Error(_('Ramdisk reported error: %s') % error,
                              data=introspection_data)

    def _store_logs(self, logs, introspection_data):
        if not CONF.processing.ramdisk_logs_dir:
            LOG.warning(
                _LW('Failed to store logs received from the ramdisk '
                    'because ramdisk_logs_dir configuration option '
                    'is not set'),
                data=introspection_data)
            return

        if not os.path.exists(CONF.processing.ramdisk_logs_dir):
            os.makedirs(CONF.processing.ramdisk_logs_dir)

        time_fmt = datetime.datetime.utcnow().strftime(self.DATETIME_FORMAT)
        bmc_address = introspection_data.get('ipmi_address', 'unknown')
        file_name = 'bmc_%s_%s' % (bmc_address, time_fmt)
        with open(os.path.join(CONF.processing.ramdisk_logs_dir, file_name),
                  'wb') as fp:
            fp.write(base64.b64decode(logs))
        LOG.info(_LI('Ramdisk logs stored in file %s'), file_name,
                 data=introspection_data)
