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

SERVICE_OPTS = [
    cfg.StrOpt('os_auth_url',
               default='http://127.0.0.1:5000/v2.0',
               help='Keystone authentication endpoint.'),
    cfg.StrOpt('os_username',
               default='',
               help='User name for accessing Keystone and Ironic API.'),
    cfg.StrOpt('os_password',
               default='',
               help='Password for accessing Keystone and Ironic API.',
               secret=True),
    cfg.StrOpt('os_tenant_name',
               default='',
               help='Tenant name for accessing Keystone and Ironic API.'),
    cfg.StrOpt('identity_uri',
               default='http://127.0.0.1:35357',
               help='Keystone admin endpoint.'),
    cfg.IntOpt('ironic_retry_attempts',
               default=5,
               help='Number of attempts to do when trying to connect to '
                    'Ironic on start up.'),
    cfg.IntOpt('ironic_retry_period',
               default=5,
               help='Amount of time between attempts to connect to Ironic '
                    'on start up.'),
    cfg.BoolOpt('manage_firewall',
                default=True,
                help='Whether to manage firewall rules for PXE port.'),
    cfg.StrOpt('dnsmasq_interface',
               default='br-ctlplane',
               help='Interface on which dnsmasq listens, the default is for '
                    'VM\'s.'),
    cfg.IntOpt('firewall_update_period',
               default=15,
               help='Amount of time in seconds, after which repeat periodic '
                    'update of firewall.'),
    cfg.StrOpt('add_ports',
               default='pxe',
               help='Which MAC addresses to add as ports during '
               'introspection. Possible values: '
               'all (all MAC addresses), active (MAC addresses of NIC with IP '
               'addresses), pxe (only MAC address of NIC node PXE booted '
               'from, falls back to "active" if PXE MAC is not supplied '
               'by the ramdisk).',
               choices=VALID_ADD_PORTS_VALUES),
    cfg.IntOpt('timeout',
               default=3600,
               help='Timeout after which introspection is considered failed, '
                    'set to 0 to disable.'),
    cfg.IntOpt('node_status_keep_time',
               default=604800,
               help='For how much time (in seconds) to keep status '
                    'information about nodes after introspection was '
                    'finished for them. Default value is 1 week.'),
    cfg.IntOpt('clean_up_period',
               default=60,
               help='Amount of time in seconds, after which repeat clean up '
                    'of timed out nodes and old nodes status information.'),
    cfg.BoolOpt('overwrite_existing',
                default=True,
                help='Whether to overwrite existing values in node database. '
                     'Disable this option to make introspection a '
                     'non-destructive operation.'),
    cfg.BoolOpt('enable_setting_ipmi_credentials',
                default=False,
                help='Whether to enable setting IPMI credentials during '
                     'introspection. This is an experimental and not well '
                     'tested feature, use at your own risk.'),
    cfg.StrOpt('listen_address',
               default='0.0.0.0',
               help='IP to listen on.'),
    cfg.IntOpt('listen_port',
               default=5050,
               help='Port to listen on.'),
    cfg.BoolOpt('authenticate',
                default=True,
                help='Whether to authenticate with Keystone on public HTTP '
                     'endpoints. Note that introspection ramdisk postback '
                     'endpoint is never authenticated.'),
    cfg.StrOpt('database',
               default='',
               help='SQLite3 database to store nodes under introspection, '
                    'required. Do not use :memory: here, it won\'t work.'),
    cfg.StrOpt('processing_hooks',
               default='scheduler,validate_interfaces',
               help='Comma-separated list of enabled hooks for processing '
                    'pipeline. Hook \'scheduler\' updates the node with the '
                    'minimum properties required by the Nova scheduler. '
                    'Hook \'validate_interfaces\' ensures that valid NIC '
                    'data was provided by the ramdisk.'
                    'Do not exclude these two unless you really know what '
                    'you\'re doing.'),
    cfg.BoolOpt('debug',
                default=False,
                help='Debug mode enabled/disabled.'),
    cfg.BoolOpt('ports_for_inactive_interfaces',
                default=False,
                help='DEPRECATED: use add_ports.'),
]

cfg.CONF.register_opts(SERVICE_OPTS, group='discoverd')


def list_opts():
    return [
        ('discoverd', SERVICE_OPTS)
    ]
