#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

from tempest import config  # noqa


baremetal_introspection_group = cfg.OptGroup(
    name="baremetal_introspection",
    title="Baremetal introspection service options",
    help="When enabling baremetal introspection tests,"
         "Ironic must be configured.")

BaremetalIntrospectionGroup = [
    cfg.StrOpt('catalog_type',
               default='baremetal-introspection',
               help="Catalog type of the baremetal provisioning service"),
    cfg.StrOpt('endpoint_type',
               default='publicURL',
               choices=['public', 'admin', 'internal',
                        'publicURL', 'adminURL', 'internalURL'],
               help="The endpoint type to use for the baremetal introspection"
                    " service"),
    cfg.IntOpt('introspection_sleep',
               default=30,
               help="Introspection sleep before check status"),
    cfg.IntOpt('introspection_timeout',
               default=600,
               help="Introspection time out"),
    cfg.IntOpt('hypervisor_update_sleep',
               default=60,
               help="Time to wait until nova becomes aware of "
                    "bare metal instances"),
    cfg.IntOpt('hypervisor_update_timeout',
               default=300,
               help="Time out for wait until nova becomes aware of "
                    "bare metal instances"),
    cfg.IntOpt('ironic_sync_timeout',
               default=60,
               help="Time it might take for Ironic--Inspector "
                    "sync to happen"),
]
