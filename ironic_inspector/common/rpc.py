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


from oslo_config import cfg
import oslo_messaging as messaging
from oslo_messaging.rpc import dispatcher

from ironic_inspector.conductor import manager

CONF = cfg.CONF

_SERVER = None
TRANSPORT = None
TOPIC = 'ironic-inspector-worker'
SERVER_NAME = 'ironic-inspector-rpc-server'


def get_transport():
    global TRANSPORT

    if TRANSPORT is None:
        TRANSPORT = messaging.get_rpc_transport(CONF, url='fake://')
    return TRANSPORT


def get_client():
    target = messaging.Target(topic=TOPIC, server=SERVER_NAME,
                              version='1.1')
    transport = get_transport()
    return messaging.RPCClient(transport, target)


def get_server():
    """Get the singleton RPC server."""
    global _SERVER

    if _SERVER is None:
        transport = get_transport()
        target = messaging.Target(topic=TOPIC, server=SERVER_NAME,
                                  version='1.1')
        mgr = manager.ConductorManager()
        _SERVER = messaging.get_rpc_server(
            transport, target, [mgr], executor='eventlet',
            access_policy=dispatcher.DefaultRPCAccessPolicy)
    return _SERVER
