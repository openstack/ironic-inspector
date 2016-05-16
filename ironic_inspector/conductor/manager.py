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

import oslo_messaging as messaging

from ironic_inspector import introspect
from ironic_inspector import process
from ironic_inspector import utils


class ConductorManager(object):
    """ironic inspector conductor manager"""
    RPC_API_VERSION = '1.1'

    target = messaging.Target(version=RPC_API_VERSION)

    @messaging.expected_exceptions(utils.Error)
    def do_introspection(self, context, node_id, token=None,
                         manage_boot=True):
        introspect.introspect(node_id, token=token, manage_boot=manage_boot)

    @messaging.expected_exceptions(utils.Error)
    def do_abort(self, context, node_id, token=None):
        introspect.abort(node_id, token=token)

    @messaging.expected_exceptions(utils.Error)
    def do_reapply(self, context, node_id, token=None):
        process.reapply(node_id)
