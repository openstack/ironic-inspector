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

from ironic_discoverd.common.i18n import _LW
from ironic_discoverd.plugins import base

LOG = logging.getLogger('ironic_discoverd.plugins.edeploy')


class eDeployHook(base.ProcessingHook):
    """Interact with eDeploy ramdisk for discovery data processing hooks."""

    def before_update(self, node, ports, node_info):
        """Store the hardware data from what has been discovered."""

        if 'data' not in node_info:
            LOG.warning(_LW('No eDeploy data was received from the ramdisk'))
            return [], {}
        # (trown) it is useful for the edeploy report tooling to have the node
        # uuid stored with the other edeploy_facts
        node_info['data'].append(['system', 'product',
                                  'ironic_uuid', node.uuid])
        return [{'op': 'add',
                 'path': '/extra/edeploy_facts',
                 'value': node_info['data']}], {}
