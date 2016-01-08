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

from oslo_config import cfg
from oslo_utils import units

from ironic_inspector.common.i18n import _, _LC, _LI, _LW
from ironic_inspector import conf
from ironic_inspector.plugins import base
from ironic_inspector import utils

CONF = cfg.CONF


LOG = utils.getProcessingLogger('ironic_inspector.plugins.standard')
KNOWN_ROOT_DEVICE_HINTS = ('model', 'vendor', 'serial', 'wwn', 'hctl',
                           'size')


class RootDiskSelectionHook(base.ProcessingHook):
    """Smarter root disk selection using Ironic root device hints.

    This hook must always go before SchedulerHook, otherwise root_disk field
    might not be updated.
    """

    def before_update(self, introspection_data, node_info, node_patches,
                      ports_patches, **kwargs):
        """Detect root disk from root device hints and IPA inventory."""
        hints = node_info.node().properties.get('root_device')
        if not hints:
            LOG.debug('Root device hints are not provided',
                      node_info=node_info, data=introspection_data)
            return

        inventory = introspection_data.get('inventory')
        if not inventory:
            LOG.error(_LW('Root device selection require ironic-python-agent '
                          'as an inspection ramdisk'),
                      node_info=node_info, data=introspection_data)
            # TODO(dtantsur): make it a real error in Mitaka cycle
            return

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
        root_disk = introspection_data.get('root_disk')
        if root_disk:
            introspection_data['local_gb'] = root_disk['size'] // units.Gi
            if CONF.processing.disk_partitioning_spacing:
                introspection_data['local_gb'] -= 1

        missing = [key for key in self.KEYS if not introspection_data.get(key)]
        if missing:
            raise utils.Error(
                _('The following required parameters are missing: %s') %
                missing, node_info=node_info, data=introspection_data)

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

    def before_processing(self, introspection_data, **kwargs):
        """Validate information about network interfaces."""
        if not introspection_data.get('interfaces'):
            raise utils.Error(_('No interfaces supplied by the ramdisk'),
                              data=introspection_data)

        valid_interfaces = {
            n: iface for n, iface in introspection_data['interfaces'].items()
            if utils.is_valid_mac(iface.get('mac'))
        }

        pxe_mac = utils.get_pxe_mac(introspection_data)

        if CONF.processing.add_ports == 'pxe' and not pxe_mac:
            LOG.warning(_LW('No boot interface provided in the introspection '
                            'data, will add all ports with IP addresses'),
                        data=introspection_data)

        if CONF.processing.add_ports == 'pxe' and pxe_mac:
            valid_interfaces = {
                n: iface for n, iface in valid_interfaces.items()
                if iface['mac'].lower() == pxe_mac
            }
        elif CONF.processing.add_ports != 'all':
            valid_interfaces = {
                n: iface for n, iface in valid_interfaces.items()
                if iface.get('ip')
            }

        if not valid_interfaces:
            raise utils.Error(_('No valid interfaces found in %s') %
                              introspection_data['interfaces'],
                              data=introspection_data)
        elif valid_interfaces != introspection_data['interfaces']:
            invalid = {n: iface
                       for n, iface in introspection_data['interfaces'].items()
                       if n not in valid_interfaces}
            LOG.warning(_LW(
                'The following interfaces were invalid or not eligible in '
                'introspection data and were excluded: %s'), invalid,
                data=introspection_data)
            LOG.info(_LI('Eligible interfaces are %s'), valid_interfaces,
                     data=introspection_data)

        introspection_data['all_interfaces'] = introspection_data['interfaces']
        introspection_data['interfaces'] = valid_interfaces
        valid_macs = [iface['mac'] for iface in valid_interfaces.values()]
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
