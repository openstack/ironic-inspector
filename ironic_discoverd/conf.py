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

import functools

from six.moves import configparser


# TODO(dtantsur): switch to oslo.db
DEFAULTS = {
    # Keystone credentials
    'os_auth_url': 'http://127.0.0.1:5000/v2.0',
    'identity_uri': 'http://127.0.0.1:35357',
    # Ironic and Keystone connection settings
    'ironic_retry_attempts': '5',
    'ironic_retry_period': '5',
    # Firewall management settings
    'manage_firewall': 'true',
    'dnsmasq_interface': 'br-ctlplane',
    'firewall_update_period': '15',
    # Introspection process settings
    'ports_for_inactive_interfaces': 'false',
    'timeout': '3600',
    'node_status_keep_time': '604800',
    'clean_up_period': '60',
    'overwrite_existing': 'false',
    'enable_setting_ipmi_credentials': 'false',
    # HTTP settings
    'listen_address': '0.0.0.0',
    'listen_port': '5050',
    'authenticate': 'true',
    # General service settings
    'processing_hooks': 'scheduler,validate_interfaces',
    'debug': 'false',
}


def with_default(func):
    @functools.wraps(func)
    def wrapper(section, option, default=None):
        try:
            return func(section, option)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default
    return wrapper


def init_conf():
    global CONF, get, getint, getboolean, read
    CONF = configparser.ConfigParser(defaults=DEFAULTS)
    get = with_default(CONF.get)
    getint = with_default(CONF.getint)
    getboolean = with_default(CONF.getboolean)
    read = CONF.read


init_conf()
