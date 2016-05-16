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
    cfg.StrOpt('listen_address',
               default='0.0.0.0',
               help=_('IP to listen on.')),
    cfg.PortOpt('listen_port',
                default=5050,
                help=_('Port to listen on.')),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help=_('Authentication method used on the ironic-inspector '
                      'API. Either "noauth" or "keystone" are currently valid '
                      'options. "noauth" will disable all authentication.')),
    cfg.IntOpt('timeout',
               default=3600,
               help=_('Timeout after which introspection is considered '
                      'failed, set to 0 to disable.')),
    cfg.IntOpt('node_status_keep_time',
               default=0,
               help=_('For how much time (in seconds) to keep status '
                      'information about nodes after introspection was '
                      'finished for them. Set to 0 (the default) '
                      'to disable the timeout.'),
               deprecated_for_removal=True),
    cfg.IntOpt('clean_up_period',
               default=60,
               help=_('Amount of time in seconds, after which repeat clean up '
                      'of timed out nodes and old nodes status information.')),
    cfg.BoolOpt('use_ssl',
                default=False,
                help=_('SSL Enabled/Disabled')),
    cfg.StrOpt('ssl_cert_path',
               default='',
               help=_('Path to SSL certificate')),
    cfg.StrOpt('ssl_key_path',
               default='',
               help=_('Path to SSL key')),
    cfg.IntOpt('max_concurrency',
               default=1000, min=2,
               help=_('The green thread pool size.')),
    cfg.IntOpt('introspection_delay',
               default=5,
               help=_('Delay (in seconds) between two introspections.')),
    cfg.ListOpt('ipmi_address_fields',
                default=['ilo_address', 'drac_host', 'drac_address',
                         'cimc_address'],
                help=_('Ironic driver_info fields that are equivalent '
                       'to ipmi_address.')),
    cfg.StrOpt('rootwrap_config',
               default="/etc/ironic-inspector/rootwrap.conf",
               help=_('Path to the rootwrap configuration file to use for '
                      'running commands as root')),
    cfg.IntOpt('api_max_limit', default=1000, min=1,
               help=_('Limit the number of elements an API list-call '
                      'returns')),
    cfg.BoolOpt('can_manage_boot', default=True,
                help=_('Whether the current installation of ironic-inspector '
                       'can manage PXE booting of nodes. If set to False, '
                       'the API will reject introspection requests with '
                       'manage_boot missing or set to True.'))
]


def register_opts(conf):
    conf.register_opts(_OPTS)


def list_opts():
    return _OPTS
