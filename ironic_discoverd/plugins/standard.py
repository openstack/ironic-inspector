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

import logging

from ironic_discoverd import conf
from ironic_discoverd.plugins import base
from ironic_discoverd import utils


LOG = logging.getLogger('ironic_discoverd.plugins.standard')


class SchedulerHook(base.ProcessingHook):
    """Nova scheduler required properties."""

    KEYS = ('cpus', 'cpu_arch', 'memory_mb', 'local_gb')

    def pre_discover(self, node_info):
        """Validate that required properties are provided by the ramdisk."""
        missing = [key for key in self.KEYS if not node_info.get(key)]
        if missing:
            LOG.error('The following required parameters are missing: %s',
                      missing)
            raise utils.DiscoveryFailed(
                'The following required parameters are missing: %s' %
                missing)

        LOG.info('Discovered data: CPUs: %(cpus)s %(cpu_arch)s, '
                 'memory %(memory_mb)s MiB, disk %(local_gb)s GiB',
                 {key: node_info.get(key) for key in self.KEYS})

    def post_discover(self, node, ports, discovered_data):
        """Update node with scheduler properties."""
        patch = [{'op': 'add', 'path': '/properties/%s' % key,
                  'value': str(discovered_data[key])}
                 for key in self.KEYS
                 if not node.properties.get(key)]
        return patch, {}


class ValidateInterfacesHook(base.ProcessingHook):
    """Hook to validate network interfaces."""

    def pre_discover(self, node_info):
        bmc_address = node_info.get('ipmi_address')

        compat = conf.getboolean('discoverd', 'ports_for_inactive_interfaces')
        if 'interfaces' not in node_info and 'macs' in node_info:
            LOG.warning('Using "macs" field is deprecated, please '
                        'update your discovery ramdisk')
            node_info['interfaces'] = {
                'dummy%d' % i: {'mac': m}
                for i, m in enumerate(node_info['macs'])}
            compat = True

        valid_interfaces = {
            n: iface for n, iface in node_info['interfaces'].items()
            if (utils.is_valid_mac(iface.get('mac'))
                and (compat or iface.get('ip')))
        }
        valid_macs = [iface['mac'] for iface in valid_interfaces.values()]
        if valid_interfaces != node_info['interfaces']:
            LOG.warning(
                'The following interfaces were invalid or not eligible in '
                'discovery data for node with BMC %(ipmi_address)s and were '
                'excluded: %(invalid)s',
                {'invalid': {n: iface
                             for n, iface in node_info['interfaces'].items()
                             if n not in valid_interfaces},
                 'ipmi_address': bmc_address})
            LOG.info('Eligible interfaces are %s', valid_interfaces)

        node_info['interfaces'] = valid_interfaces
        node_info['macs'] = valid_macs


class RamdiskErrorHook(base.ProcessingHook):
    """Hook to process error send from the ramdisk."""

    def pre_discover(self, node_info):
        if not node_info.get('error'):
            return

        LOG.error('Error happened during discovery: %s', node_info['error'])
        raise utils.DiscoveryFailed(node_info['error'])
