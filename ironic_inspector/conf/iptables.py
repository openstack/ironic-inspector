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
    cfg.BoolOpt('manage_firewall',
                default=True,
                # NOTE(milan) this filter driver will be replaced by
                # a dnsmasq filter driver
                deprecated_for_removal=True,
                deprecated_group='firewall',
                help=_('Whether to manage firewall rules for PXE port. '
                       'This configuration option was deprecated in favor of '
                       'the ``driver`` option in the ``pxe_filter`` section. '
                       'Please, use the ``noop`` filter driver to disable the '
                       'firewall filtering or the ``iptables`` filter driver '
                       'to enable it.')),
    cfg.StrOpt('dnsmasq_interface',
               default='br-ctlplane',
               deprecated_group='firewall',
               help=_('Interface on which dnsmasq listens, the default is for '
                      'VM\'s.')),
    cfg.StrOpt('firewall_chain',
               default='ironic-inspector',
               deprecated_group='firewall',
               help=_('iptables chain name to use.')),
    cfg.ListOpt('ethoib_interfaces',
                deprecated_group='firewall',
                default=[],
                help=_('List of Etherent Over InfiniBand interfaces '
                       'on the Inspector host which are used for physical '
                       'access to the DHCP network. Multiple interfaces would '
                       'be attached to a bond or bridge specified in '
                       'dnsmasq_interface. The MACs of the InfiniBand nodes '
                       'which are not in desired state are going to be '
                       'blacklisted based on the list of neighbor MACs '
                       'on these interfaces.')),
]


def register_opts(conf):
    conf.register_opts(_OPTS, 'iptables')


def list_opts():
    return _OPTS
