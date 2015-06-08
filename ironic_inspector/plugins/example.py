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

"""Example plugin."""

import logging

from ironic_inspector.plugins import base


LOG = logging.getLogger('ironic_inspector.plugins.example')


class ExampleProcessingHook(base.ProcessingHook):  # pragma: no cover
    def before_processing(self, introspection_data):
        LOG.debug('before_processing: %s', introspection_data)

    def before_update(self, node, ports, introspection_data):
        LOG.debug('before_update: %s (node %s)', introspection_data, node.uuid)
