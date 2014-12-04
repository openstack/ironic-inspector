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

from six.moves import configparser


DEFAULTS = {
    'debug': 'false',
    'listen_address': '0.0.0.0',
    'listen_port': '5050',
    'dnsmasq_interface': 'br-ctlplane',
    'authenticate': 'true',
    'firewall_update_period': '15',
    'ports_for_inactive_interfaces': 'false',
    'ironic_retry_attempts': '5',
    'ironic_retry_period': '5',
    'database': '',
    'processing_hooks': 'scheduler',
    'timeout': '3600',
    'clean_up_period': '60',
}


def init_conf():
    global CONF, get, getint, getboolean, read
    CONF = configparser.ConfigParser(defaults=DEFAULTS)
    get = CONF.get
    getint = CONF.getint
    getboolean = CONF.getboolean
    read = CONF.read


init_conf()
