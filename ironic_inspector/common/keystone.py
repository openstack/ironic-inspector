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

from keystoneauth1 import exceptions
from keystoneauth1 import loading
from oslo_config import cfg
from oslo_log import log
from six.moves.urllib import parse  # for legacy options loading only

from ironic_inspector.common.i18n import _LW

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def register_auth_opts(group):
    loading.register_session_conf_options(CONF, group)
    loading.register_auth_conf_options(CONF, group)
    CONF.set_default('auth_type', default='password', group=group)


def get_session(group, legacy_mapping=None, legacy_auth_opts=None):
    auth = _get_auth(group, legacy_mapping, legacy_auth_opts)
    session = loading.load_session_from_conf_options(
        CONF, group, auth=auth)
    return session


def _get_auth(group, legacy_mapping=None, legacy_opts=None):
    try:
        auth = loading.load_auth_from_conf_options(CONF, group)
    except exceptions.MissingRequiredOptions:
        auth = _get_legacy_auth(group, legacy_mapping, legacy_opts)
    else:
        if auth is None:
            auth = _get_legacy_auth(group, legacy_mapping, legacy_opts)
    return auth


def _get_legacy_auth(group, legacy_mapping, legacy_opts):
    """Load auth plugin from legacy options.

    If legacy_opts is not empty, these options will be registered first.

    legacy_mapping is a dict that maps the following keys to legacy option
    names:
        auth_url
        username
        password
        tenant_name
    """
    LOG.warning(_LW("Group [%s]: Using legacy auth loader is deprecated. "
                    "Consider specifying appropriate keystone auth plugin as "
                    "'auth_type' and corresponding plugin options."), group)
    if legacy_opts:
        for opt in legacy_opts:
            try:
                CONF.register_opt(opt, group=group)
            except cfg.DuplicateOptError:
                pass

    conf = getattr(CONF, group)
    auth_params = {a: getattr(conf, legacy_mapping[a])
                   for a in legacy_mapping}
    legacy_loader = loading.get_plugin_loader('password')
    # NOTE(pas-ha) only Swift had this option, take it into account
    try:
        auth_version = conf.get('os_auth_version')
    except cfg.NoSuchOptError:
        auth_version = None
    # NOTE(pas-ha) mimic defaults of keystoneclient
    if _is_apiv3(auth_params['auth_url'], auth_version):
        auth_params.update({
            'project_domain_id': 'default',
            'user_domain_id': 'default'})
    return legacy_loader.load_from_options(**auth_params)


# NOTE(pas-ha): for backward compat with legacy options loading only
def _is_apiv3(auth_url, auth_version):
    """Check if V3 version of API is being used or not.

    This method inspects auth_url and auth_version, and checks whether V3
    version of the API is being used or not.
    When no auth_version is specified and auth_url is not a versioned
    endpoint, v2.0 is assumed.
    :param auth_url: a http or https url to be inspected (like
        'http://127.0.0.1:9898/').
    :param auth_version: a string containing the version (like 'v2', 'v3.0')
                         or None
    :returns: True if V3 of the API is being used.
    """
    return (auth_version in ('v3.0', '3') or
            '/v3' in parse.urlparse(auth_url).path)


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
