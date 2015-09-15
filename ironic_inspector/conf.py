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


VALID_ADD_PORTS_VALUES = ('all', 'active', 'pxe')
VALID_KEEP_PORTS_VALUES = ('all', 'present', 'added')
VALID_STORE_DATA_VALUES = ('none', 'swift')


IRONIC_OPTS = [
    cfg.StrOpt('os_auth_url',
               default='',
               help='Keystone authentication endpoint for accessing Ironic '
                    'API. Use [keystone_authtoken]/auth_uri for keystone '
                    'authentication.',
               deprecated_group='discoverd'),
    cfg.StrOpt('os_username',
               default='',
               help='User name for accessing Ironic API. '
                    'Use [keystone_authtoken]/admin_user for keystone '
                    'authentication.',
               deprecated_group='discoverd'),
    cfg.StrOpt('os_password',
               default='',
               help='Password for accessing Ironic API. '
                    'Use [keystone_authtoken]/admin_password for keystone '
                    'authentication.',
               secret=True,
               deprecated_group='discoverd'),
    cfg.StrOpt('os_tenant_name',
               default='',
               help='Tenant name for accessing Ironic API. '
                    'Use [keystone_authtoken]/admin_tenant_name for keystone '
                    'authentication.',
               deprecated_group='discoverd'),
    cfg.StrOpt('identity_uri',
               default='',
               help='Keystone admin endpoint. '
                    'DEPRECATED: use [keystone_authtoken]/identity_uri.',
               deprecated_group='discoverd',
               deprecated_for_removal=True),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help='Method to use for authentication: noauth or keystone.'),
    cfg.StrOpt('ironic_url',
               default='http://localhost:6385/',
               help='Ironic API URL, used to set Ironic API URL when '
                    'auth_strategy option is noauth to work with standalone '
                    'Ironic without keystone.'),
    cfg.StrOpt('os_service_type',
               default='baremetal',
               help='Ironic service type.'),
    cfg.StrOpt('os_endpoint_type',
               default='internalURL',
               help='Ironic endpoint type.'),
    cfg.IntOpt('retry_interval',
               default=2,
               help='Interval between retries in case of conflict error '
               '(HTTP 409).'),
    cfg.IntOpt('max_retries',
               default=30,
               help='Maximum number of retries in case of conflict error '
               '(HTTP 409).'),
]


FIREWALL_OPTS = [
    cfg.BoolOpt('manage_firewall',
                default=True,
                help='Whether to manage firewall rules for PXE port.',
                deprecated_group='discoverd'),
    cfg.StrOpt('dnsmasq_interface',
               default='br-ctlplane',
               help='Interface on which dnsmasq listens, the default is for '
                    'VM\'s.',
               deprecated_group='discoverd'),
    cfg.IntOpt('firewall_update_period',
               default=15,
               help='Amount of time in seconds, after which repeat periodic '
                    'update of firewall.',
               deprecated_group='discoverd'),
    cfg.StrOpt('firewall_chain',
               default='ironic-inspector',
               help='iptables chain name to use.'),
]


PROCESSING_OPTS = [
    cfg.StrOpt('add_ports',
               default='pxe',
               help='Which MAC addresses to add as ports during '
               'introspection. Possible values: '
               'all (all MAC addresses), active (MAC addresses of NIC with IP '
               'addresses), pxe (only MAC address of NIC node PXE booted '
               'from, falls back to "active" if PXE MAC is not supplied '
               'by the ramdisk).',
               choices=VALID_ADD_PORTS_VALUES,
               deprecated_group='discoverd'),
    cfg.StrOpt('keep_ports',
               default='all',
               help='Which ports (already present on a node) to keep after '
               'introspection. Possible values: '
               'all (do not delete anything), present (keep ports which MACs '
               'were present in introspection data), added (keep only MACs '
               'that we added during introspection).',
               choices=VALID_KEEP_PORTS_VALUES,
               deprecated_group='discoverd'),
    cfg.BoolOpt('overwrite_existing',
                default=True,
                help='Whether to overwrite existing values in node database. '
                     'Disable this option to make introspection a '
                     'non-destructive operation.',
                deprecated_group='discoverd'),
    cfg.BoolOpt('enable_setting_ipmi_credentials',
                default=False,
                help='Whether to enable setting IPMI credentials during '
                     'introspection. This is an experimental and not well '
                     'tested feature, use at your own risk.',
                deprecated_group='discoverd'),
    cfg.StrOpt('default_processing_hooks',
               default='ramdisk_error,root_disk_selection,scheduler,'
                       'validate_interfaces',
               help='Comma-separated list of default hooks for processing '
                    'pipeline. Hook \'scheduler\' updates the node with the '
                    'minimum properties required by the Nova scheduler. '
                    'Hook \'validate_interfaces\' ensures that valid NIC '
                    'data was provided by the ramdisk.'
                    'Do not exclude these two unless you really know what '
                    'you\'re doing.'),
    cfg.StrOpt('processing_hooks',
               default='$default_processing_hooks',
               help='Comma-separated list of enabled hooks for processing '
                    'pipeline. The default for this is '
                    '$default_processing_hooks, hooks can be added before '
                    'or after the defaults like this: '
                    '"prehook,$default_processing_hooks,posthook".',
               deprecated_group='discoverd'),
    cfg.StrOpt('ramdisk_logs_dir',
               help='If set, logs from ramdisk will be stored in this '
               'directory.',
               deprecated_group='discoverd'),
    cfg.BoolOpt('always_store_ramdisk_logs',
                default=False,
                help='Whether to store ramdisk logs even if it did not return '
                'an error message (dependent upon "ramdisk_logs_dir" option '
                'being set).',
                deprecated_group='discoverd'),
    cfg.StrOpt('node_not_found_hook',
               default=None,
               help='The name of the hook to run when inspector receives '
                    'inspection information from a node it isn\'t already '
                    'aware of. This hook is ignored by default.'),
    cfg.StrOpt('store_data',
               default='none',
               choices=VALID_STORE_DATA_VALUES,
               help='Method for storing introspection data. If set to \'none'
                    '\', introspection data will not be stored.'),
    cfg.StrOpt('store_data_location',
               default=None,
               help='Name of the key to store the location of stored data in '
                    'the extra column of the Ironic database.'),
    cfg.BoolOpt('disk_partitioning_spacing',
                default=True,
                help='Whether to leave 1 GiB of disk size untouched for '
                     'partitioning. Only has effect when used with the IPA '
                     'as a ramdisk, for older ramdisk local_gb is '
                     'calculated on the ramdisk side.'),
]


DISCOVERD_OPTS = [
    cfg.StrOpt('database',
               default='',
               help='SQLite3 database to store nodes under introspection, '
                    'required. Do not use :memory: here, it won\'t work. '
                    'DEPRECATED: use [database]/connection.',
               deprecated_for_removal=True),
]

SERVICE_OPTS = [
    cfg.StrOpt('listen_address',
               default='0.0.0.0',
               help='IP to listen on.',
               deprecated_group='discoverd'),
    cfg.IntOpt('listen_port',
               default=5050,
               help='Port to listen on.',
               deprecated_group='discoverd'),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help='Authentication method used on the ironic-inspector '
                    'API. Either "noauth" or "keystone" are currently valid '
                    'options. "noauth" will disable all authentication.'),
    cfg.BoolOpt('authenticate',
                default=None,
                help='DEPRECATED: use auth_strategy.',
                deprecated_group='discoverd',
                deprecated_for_removal=True),
    cfg.IntOpt('timeout',
               default=3600,
               help='Timeout after which introspection is considered failed, '
                    'set to 0 to disable.',
               deprecated_group='discoverd'),
    cfg.IntOpt('node_status_keep_time',
               default=604800,
               help='For how much time (in seconds) to keep status '
                    'information about nodes after introspection was '
                    'finished for them. Default value is 1 week.',
               deprecated_group='discoverd'),
    cfg.IntOpt('clean_up_period',
               default=60,
               help='Amount of time in seconds, after which repeat clean up '
                    'of timed out nodes and old nodes status information.',
               deprecated_group='discoverd'),
    cfg.BoolOpt('use_ssl',
                default=False,
                help='SSL Enabled/Disabled'),
    cfg.StrOpt('ssl_cert_path',
               default='',
               help='Path to SSL certificate'),
    cfg.StrOpt('ssl_key_path',
               default='',
               help='Path to SSL key'),
    cfg.IntOpt('max_concurrency',
               default=1000,
               help='The green thread pool size.'),
    cfg.IntOpt('introspection_delay',
               default=5,
               help='Delay (in seconds) between two introspections.'),
    cfg.StrOpt('introspection_delay_drivers',
               default='^.*_ssh$',
               help='Only node with drivers matching this regular expression '
               'will be affected by introspection_delay setting.'),
    cfg.ListOpt('ipmi_address_fields',
                default=['ilo_address', 'drac_host', 'cimc_address'],
                help='Ironic driver_info fields that are equivalent '
                'to ipmi_address.'),
    cfg.StrOpt('rootwrap_config',
               default="/etc/ironic-inspector/rootwrap.conf",
               help='Path to the rootwrap configuration file to use for '
                    'running commands as root'),
]


cfg.CONF.register_opts(SERVICE_OPTS)
cfg.CONF.register_opts(FIREWALL_OPTS, group='firewall')
cfg.CONF.register_opts(PROCESSING_OPTS, group='processing')
cfg.CONF.register_opts(IRONIC_OPTS, group='ironic')
cfg.CONF.register_opts(DISCOVERD_OPTS, group='discoverd')


def list_opts():
    return [
        ('', SERVICE_OPTS),
        ('firewall', FIREWALL_OPTS),
        ('ironic', IRONIC_OPTS),
        ('processing', PROCESSING_OPTS),
        ('discoverd', DISCOVERD_OPTS),
    ]
