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
TRANSPORT = None


def init():
    global TRANSPORT
    TRANSPORT = messaging.get_rpc_transport(CONF)


def get_client(topic=None):
    """Get a RPC client instance.

    :param topic: The topic of the message will be delivered to. This argument
                  is ignored if CONF.standalone is True.
    """
    assert TRANSPORT is not None
    if CONF.standalone:
        target = messaging.Target(topic=manager.MANAGER_TOPIC,
                                  server=CONF.host,
                                  version='1.3')
    else:
        target = messaging.Target(topic=topic, version='1.3')
    return messaging.get_rpc_client(TRANSPORT, target)


def get_server(endpoints):
    """Get a RPC server instance."""

    assert TRANSPORT is not None
    target = messaging.Target(topic=manager.MANAGER_TOPIC, server=CONF.host,
                              version='1.3')
    return messaging.get_rpc_server(
        TRANSPORT, target, endpoints, executor='eventlet',
        access_policy=dispatcher.DefaultRPCAccessPolicy)
