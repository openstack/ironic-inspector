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

from ironic_inspector.common.i18n import _


_OPTS = [
    cfg.ListOpt('cidr_map',
                default=[],
                sample_default=('10.10.10.0/24:physnet_a,'
                                '2001:db8::/64:physnet_b'),
                help=_('Mapping of IP subnet CIDR to physical network. When '
                       'the physnet_cidr_map processing hook is enabled the '
                       'physical_network property of baremetal ports is '
                       'populated based on this mapping.')),
]


def register_opts(conf):
    conf.register_opts(_OPTS, group='port_physnet')


def list_opts():
    return _OPTS
