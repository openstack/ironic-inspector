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

"""Nova scheduler required properties."""

import logging

from ironic_discoverd.plugins import base
from ironic_discoverd import utils


LOG = logging.getLogger('ironic_discoverd.plugins.scheduler')


class SchedulerHook(base.ProcessingHook):
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
