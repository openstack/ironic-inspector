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

See https://blueprints.launchpad.net/ironic-inspector/+spec/edeploy for
details on how to use it. Note that this plugin requires a special ramdisk.
"""

import json
import logging

from oslo_config import cfg

from ironic_inspector.common.i18n import _LW
from ironic_inspector.common import swift
from ironic_inspector.plugins import base

CONF = cfg.CONF


LOG = logging.getLogger('ironic_inspector.plugins.edeploy')


class eDeployHook(base.ProcessingHook):
    """Processing hook for saving additional data from eDeploy ramdisk."""

    def _store_extra_hardware(self, name, data):
        """Handles storing the extra hardware data from the ramdisk"""
        swift_api = swift.SwiftAPI()
        swift_api.create_object(name, data)

    def before_update(self, introspection_data, node_info, node_patches,
                      ports_patches, **kwargs):
        """Stores the 'data' key from introspection_data in Swift.

        If the 'data' key exists, updates Ironic extra column
        'hardware_swift_object' key to the name of the Swift object, and stores
        the data in the 'inspector' container in Swift.

        Otherwise, it does nothing.
        """
        if 'data' not in introspection_data:
            LOG.warning(_LW('No extra hardware information was received from '
                            'the ramdisk'))
            return

        name = 'extra_hardware-%s' % node_info.uuid
        self._store_extra_hardware(name,
                                   json.dumps(introspection_data['data']))

        node_patches.append({'op': 'add',
                             'path': '/extra/hardware_swift_object',
                             'value': name})
