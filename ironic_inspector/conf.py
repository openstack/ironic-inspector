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
from oslo_middleware import cors

from ironic_inspector.common.i18n import _


MIN_VERSION_HEADER = 'X-OpenStack-Ironic-Inspector-API-Minimum-Version'
MAX_VERSION_HEADER = 'X-OpenStack-Ironic-Inspector-API-Maximum-Version'
VERSION_HEADER = 'X-OpenStack-Ironic-Inspector-API-Version'

VALID_ADD_PORTS_VALUES = ('all', 'active', 'pxe')
VALID_KEEP_PORTS_VALUES = ('all', 'present', 'added')
VALID_STORE_DATA_VALUES = ('none', 'swift')


FIREWALL_OPTS = [
    cfg.BoolOpt('manage_firewall',
                default=True,
                help=_('Whether to manage firewall rules for PXE port.')),
    cfg.StrOpt('dnsmasq_interface',
               default='br-ctlplane',
               help=_('Interface on which dnsmasq listens, the default is for '
                      'VM\'s.')),
    cfg.IntOpt('firewall_update_period',
               default=15,
               help=_('Amount of time in seconds, after which repeat periodic '
                      'update of firewall.')),
    cfg.StrOpt('firewall_chain',
               default='ironic-inspector',
               help=_('iptables chain name to use.')),
    cfg.ListOpt('ethoib_interfaces',
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

PROCESSING_OPTS = [
    cfg.StrOpt('add_ports',
               default='pxe',
               help=_('Which MAC addresses to add as ports during '
                      'introspection. Possible values: all '
                      '(all MAC addresses), active (MAC addresses of NIC with '
                      'IP addresses), pxe (only MAC address of NIC node PXE '
                      'booted from, falls back to "active" if PXE MAC is not '
                      'supplied by the ramdisk).'),
               choices=VALID_ADD_PORTS_VALUES),
    cfg.StrOpt('keep_ports',
               default='all',
               help=_('Which ports (already present on a node) to keep after '
                      'introspection. Possible values: all (do not delete '
                      'anything), present (keep ports which MACs were present '
                      'in introspection data), added (keep only MACs that we '
                      'added during introspection).'),
               choices=VALID_KEEP_PORTS_VALUES),
    cfg.BoolOpt('overwrite_existing',
                default=True,
                help=_('Whether to overwrite existing values in node '
                       'database. Disable this option to make '
                       'introspection a non-destructive operation.')),
    cfg.BoolOpt('enable_setting_ipmi_credentials',
                default=False,
                help=_('Whether to enable setting IPMI credentials during '
                       'introspection. This feature will be removed in the '
                       'Pike release.'),
                deprecated_for_removal=True),
    cfg.StrOpt('default_processing_hooks',
               default='ramdisk_error,root_disk_selection,scheduler,'
                       'validate_interfaces,capabilities,pci_devices',
               help=_('Comma-separated list of default hooks for processing '
                      'pipeline. Hook \'scheduler\' updates the node with the '
                      'minimum properties required by the Nova scheduler. '
                      'Hook \'validate_interfaces\' ensures that valid NIC '
                      'data was provided by the ramdisk. '
                      'Do not exclude these two unless you really know what '
                      'you\'re doing.')),
    cfg.StrOpt('processing_hooks',
               default='$default_processing_hooks',
               help=_('Comma-separated list of enabled hooks for processing '
                      'pipeline. The default for this is '
                      '$default_processing_hooks, hooks can be added before '
                      'or after the defaults like this: '
                      '"prehook,$default_processing_hooks,posthook".')),
    cfg.StrOpt('ramdisk_logs_dir',
               help=_('If set, logs from ramdisk will be stored in this '
                      'directory.')),
    cfg.BoolOpt('always_store_ramdisk_logs',
                default=False,
                help=_('Whether to store ramdisk logs even if it did not '
                       'return an error message (dependent upon '
                       '"ramdisk_logs_dir" option being set).')),
    cfg.StrOpt('node_not_found_hook',
               help=_('The name of the hook to run when inspector receives '
                      'inspection information from a node it isn\'t already '
                      'aware of. This hook is ignored by default.')),
    cfg.StrOpt('store_data',
               default='none',
               choices=VALID_STORE_DATA_VALUES,
               help=_('Method for storing introspection data. If set to \'none'
                      '\', introspection data will not be stored.')),
    cfg.StrOpt('store_data_location',
               help=_('Name of the key to store the location of stored data '
                      'in the extra column of the Ironic database.')),
    cfg.BoolOpt('disk_partitioning_spacing',
                default=True,
                help=_('Whether to leave 1 GiB of disk size untouched for '
                       'partitioning. Only has effect when used with the IPA '
                       'as a ramdisk, for older ramdisk local_gb is '
                       'calculated on the ramdisk side.')),
    cfg.BoolOpt('log_bmc_address',
                default=True,
                help=_('Whether to log node BMC address with every message '
                       'during processing.'),
                deprecated_for_removal=True),
    cfg.StrOpt('ramdisk_logs_filename_format',
               default='{uuid}_{dt:%Y%m%d-%H%M%S.%f}.tar.gz',
               help=_('File name template for storing ramdisk logs. The '
                      'following replacements can be used: '
                      '{uuid} - node UUID or "unknown", '
                      '{bmc} - node BMC address or "unknown", '
                      '{dt} - current UTC date and time, '
                      '{mac} - PXE booting MAC or "unknown".')),
    cfg.BoolOpt('power_off',
                default=True,
                help=_('Whether to power off a node after introspection.')),
]

SERVICE_OPTS = [
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
               default=604800,
               help=_('For how much time (in seconds) to keep status '
                      'information about nodes after introspection was '
                      'finished for them. Default value is 1 week.')),
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
    cfg.StrOpt('introspection_delay_drivers',
               default='.*',
               help=_('Only node with drivers matching this regular '
                      'expression will be affected by introspection_delay '
                      'setting.'),
               deprecated_for_removal=True),
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
               help=_('Limit the number of elements an API list-call returns'))
]


cfg.CONF.register_opts(SERVICE_OPTS)
cfg.CONF.register_opts(FIREWALL_OPTS, group='firewall')
cfg.CONF.register_opts(PROCESSING_OPTS, group='processing')


def list_opts():
    return [
        ('', SERVICE_OPTS),
        ('firewall', FIREWALL_OPTS),
        ('processing', PROCESSING_OPTS),
    ]


def set_config_defaults():
    """This method updates all configuration default values."""
    set_cors_middleware_defaults()


def set_cors_middleware_defaults():
    """Update default configuration options for oslo.middleware."""
    # TODO(krotscheck): Update with https://review.openstack.org/#/c/285368/
    cfg.set_defaults(
        cors.CORS_OPTS,
        allow_headers=['X-Auth-Token',
                       MIN_VERSION_HEADER,
                       MAX_VERSION_HEADER,
                       VERSION_HEADER],
        allow_methods=['GET', 'POST', 'PUT', 'HEAD',
                       'PATCH', 'DELETE', 'OPTIONS']
    )
