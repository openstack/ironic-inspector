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

"""eDeploy hardware detection and classification plugin.

See https://blueprints.launchpad.net/ironic-discoverd/+spec/edeploy for
details on how to use it. Note that this plugin requires a special ramdisk.
"""

import logging

from hardware import matcher
from hardware import state

from ironic_discoverd.common.i18n import _, _LW
from ironic_discoverd import conf
from ironic_discoverd.plugins import base
from ironic_discoverd import utils


LOG = logging.getLogger('ironic_discoverd.plugins.edeploy')


class eDeployHook(base.ProcessingHook):
    """Interact with eDeploy ramdisk for discovery data processing hooks."""

    def before_processing(self, node_info):
        """Hook to run before data processing.

        Finds matching profile in the database.

        :param node_info: raw information sent by the ramdisk, may be modified
                          by the hook.
        :raises: Error if node_info does not contain extended information
        :returns: nothing.
        """

        if 'data' not in node_info:
            raise utils.Error(
                _('edeploy plugin: no "data" key in the received JSON'))

        LOG.debug('before_processing: %s', node_info['data'])

        hw_items = []
        for info in node_info['data']:
            hw_items.append(tuple(info))

        hw_copy = list(hw_items)
        self._process_data_for_discoverd(hw_copy, node_info)
        sobj = None

        try:
            sobj = state.State(lockname=conf.get('edeploy', 'lockname',
                                                 '/var/lock/discoverd.lock'))
            sobj.load(conf.get('edeploy', 'configdir', '/etc/edeploy'))
            prof, var = sobj.find_match(hw_items)
            var['profile'] = prof

            if 'logical_disks' in var:
                node_info['target_raid_configuration'] = {
                    'logical_disks': var.pop('logical_disks')}

            if 'bios_settings' in var:
                node_info['bios_settings'] = var.pop('bios_settings')

            node_info['hardware'] = var

        except Exception as excpt:
            LOG.warning(_LW(
                'Unable to find a matching hardware profile: %s'), excpt)
        finally:
            if sobj:
                sobj.save()
                sobj.unlock()
        del node_info['data']

    def _process_data_for_discoverd(self, hw_items, node_info):
        matcher.match_spec(('memory', 'total', 'size', '$memory_mb'),
                           hw_items, node_info)
        matcher.match_spec(('cpu', 'logical', 'number', '$cpus'),
                           hw_items, node_info)
        matcher.match_spec(('system', 'kernel', 'arch', '$cpu_arch'),
                           hw_items, node_info)
        matcher.match_spec(('disk', '$disk', 'size', '$local_gb'),
                           hw_items, node_info)
        matcher.match_spec(('ipmi', 'lan', 'ip-address', '$ipmi_address'),
                           hw_items, node_info)
        node_info['interfaces'] = {}
        while True:
            info = {'ipv4': 'none'}
            if not matcher.match_spec(('network', '$iface', 'serial', '$mac'),
                                      hw_items, info):
                break
            matcher.match_spec(('network', info['iface'], 'ipv4', '$ipv4'),
                               hw_items, info)
            node_info['interfaces'][info['iface']] = {'mac': info['mac'],
                                                      'ip': info['ipv4']}

    def before_update(self, node, ports, node_info):
        """Store the hardware data from what has been discovered."""

        patches = []

        if 'hardware' in node_info:
            capabilities_dict = utils.capabilities_to_dict(
                node.properties.get('capabilities'))
            capabilities_dict['profile'] = node_info['hardware']['profile']

            patches.append({'op': 'add',
                            'path': '/extra/configdrive_metadata',
                            'value': {'hardware': node_info['hardware']}})
            patches.append(
                {'op': 'add',
                 'path': '/properties/capabilities',
                 'value': utils.dict_to_capabilities(capabilities_dict)})

            if 'target_raid_configuration' in node_info:
                patches.append(
                    {'op': 'add',
                     'path': '/extra/target_raid_configuration',
                     'value': node_info['target_raid_configuration']})

            if 'bios_settings' in node_info:
                patches.append(
                    {'op': 'add',
                     'path': '/extra/bios_settings',
                     'value': node_info['bios_settings']})

        return patches, {}
