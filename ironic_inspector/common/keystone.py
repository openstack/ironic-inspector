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

import copy

from keystoneauth1 import loading
from oslo_config import cfg


CONF = cfg.CONF


def register_auth_opts(group):
    loading.register_session_conf_options(CONF, group)
    loading.register_auth_conf_options(CONF, group)
    CONF.set_default('auth_type', default='password', group=group)


def get_session(group):
    auth = loading.load_auth_from_conf_options(CONF, group)
    session = loading.load_session_from_conf_options(
        CONF, group, auth=auth)
    return session


def add_auth_options(options, group):

    def add_options(opts, opts_to_add):
        for new_opt in opts_to_add:
            for opt in opts:
                if opt.name == new_opt.name:
                    break
            else:
                opts.append(new_opt)

    opts = copy.deepcopy(options)
    opts.insert(0, loading.get_auth_common_conf_options()[0])
    # NOTE(dims): There are a lot of auth plugins, we just generate
    # the config options for a few common ones
    plugins = ['password', 'v2password', 'v3password']
    for name in plugins:
        plugin = loading.get_plugin_loader(name)
        add_options(opts, loading.get_auth_plugin_conf_options(plugin))
    add_options(opts, loading.get_session_conf_options())
    opts.sort(key=lambda x: x.name)
    return [(group, opts)]
