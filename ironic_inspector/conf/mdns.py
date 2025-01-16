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
from oslo_config import types as cfg_types

opts = [
    cfg.IntOpt('registration_attempts',
               min=1, default=5,
               help='Number of attempts to register a service. Currently '
                    'has to be larger than 1 because of race conditions '
                    'in the zeroconf library.'),
    cfg.IntOpt('lookup_attempts',
               min=1, default=3,
               help='Number of attempts to lookup a service.'),
    cfg.Opt('params',
            # This is required for values that contain commas.
            type=cfg_types.Dict(cfg_types.String(quotes=True)),
            default={},
            help='Additional parameters to pass for the registered '
                 'service.'),
    cfg.ListOpt('interfaces',
                help='List of IP addresses of interfaces to use for mDNS. '
                     'Defaults to all interfaces on the system.'),
]

CONF = cfg.CONF
opt_group = cfg.OptGroup(name='mdns', title='Options for multicast DNS')


def register_opts(conf):
    conf.register_group(opt_group)
    conf.register_opts(opts, group=opt_group)
