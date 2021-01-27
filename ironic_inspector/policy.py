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

import itertools
import sys

from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import versionutils
from oslo_policy import opts
from oslo_policy import policy

CONF = cfg.CONF

_ENFORCER = None

# TODO(gmann): Remove setting the default value of config policy_file
# once oslo_policy change the default value to 'policy.yaml'.
# https://github.com/openstack/oslo.policy/blob/a626ad12fe5a3abd49d70e3e5b95589d279ab578/oslo_policy/opts.py#L49
DEFAULT_POLICY_FILE = 'policy.yaml'
opts.set_defaults(cfg.CONF, DEFAULT_POLICY_FILE)

# Generic policy check string for system administrators. These are the people
# who need the highest level of authorization to operate the deployment.
# They're allowed to create, read, update, or delete any system-specific
# resource. They can also operate on project-specific resources where
# applicable (e.g., cleaning up baremetal hosts)
SYSTEM_ADMIN = 'role:admin and system_scope:all'

# Generic policy check string for system users who don't require all the
# authorization that system administrators typically have. This persona, or
# check string, typically isn't used by default, but it's existence it useful
# in the event a deployment wants to offload some administrative action from
# system administrator to system members
SYSTEM_MEMBER = 'role:member and system_scope:all'

# Generic policy check string for read-only access to system-level resources.
# This persona is useful for someone who needs access for auditing or even
# support. These uses are also able to view project-specific resources where
# applicable (e.g., listing all volumes in the deployment, regardless of the
# project they belong to).
SYSTEM_READER = 'role:reader and system_scope:all'

deprecated_node_reason = """
The inspector API is now aware of system scope and default roles.
"""

default_policies = [
    policy.RuleDefault(
        'is_admin',
        'role:admin or role:administrator or role:baremetal_admin',
        description='Full read/write API access',
        deprecated_for_removal=True,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY),
    policy.RuleDefault(
        'is_observer',
        'role:baremetal_observer',
        description='Read-only API access',
        deprecated_for_removal=True,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY),
    policy.RuleDefault(
        'public_api',
        'is_public_api:True',
        description='Internal flag for public API routes'),
    policy.RuleDefault(
        'default',
        '!',
        description='Default API access policy'),
]

api_version_policies = [
    policy.DocumentedRuleDefault(
        'introspection',
        'rule:public_api',
        'Access the API root for available versions information',
        [{'path': '/', 'method': 'GET'}]
    ),
    policy.DocumentedRuleDefault(
        'introspection:version',
        'rule:public_api',
        'Access the versioned API root for version information',
        [{'path': '/{version}', 'method': 'GET'}]
    ),
]


deprecated_introspection_status = policy.DeprecatedRule(
    name='introspection:status',
    check_str='rule:is_admin or rule:is_observer'
)
deprecated_introspection_start = policy.DeprecatedRule(
    name='introspection:start',
    check_str='rule:is_admin'
)
deprecated_introspection_abort = policy.DeprecatedRule(
    name='introspection:abort',
    check_str='rule:is_admin'
)
deprecated_introspection_data = policy.DeprecatedRule(
    name='introspection:data',
    check_str='rule:is_admin'
)
deprecated_introspection_reapply = policy.DeprecatedRule(
    name='introspection:reapply',
    check_str='rule:is_admin'
)
deprecated_introspection_rule_get = policy.DeprecatedRule(
    name='introspection:rule:get',
    check_str='rule:is_admin'
)
deprecated_introspection_rule_delete = policy.DeprecatedRule(
    name='introspection:rule:delete',
    check_str='rule:is_admin'
)
deprecated_introspection_rule_create = policy.DeprecatedRule(
    name='introspection:rule:create',
    check_str='rule:is_admin'
)

introspection_policies = [
    policy.DocumentedRuleDefault(
        name='introspection:continue',
        check_str='rule:public_api',
        description='Ramdisk callback to continue introspection',
        operations=[{'path': '/continue', 'method': 'POST'}],
    ),
    policy.DocumentedRuleDefault(
        name='introspection:status',
        check_str=SYSTEM_READER,
        description='Get introspection status',
        operations=[{'path': '/introspection', 'method': 'GET'},
                    {'path': '/introspection/{node_id}', 'method': 'GET'}],
        deprecated_rule=deprecated_introspection_status,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name='introspection:start',
        check_str=SYSTEM_ADMIN,
        description='Start introspection',
        operations=[{'path': '/introspection/{node_id}', 'method': 'POST'}],
        deprecated_rule=deprecated_introspection_start,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name='introspection:abort',
        check_str=SYSTEM_ADMIN,
        description='Abort introspection',
        operations=[{'path': '/introspection/{node_id}/abort',
                     'method': 'POST'}],
        deprecated_rule=deprecated_introspection_abort,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name='introspection:data',
        check_str=SYSTEM_ADMIN,
        description='Get introspection data',
        operations=[{'path': '/introspection/{node_id}/data',
                     'method': 'GET'}],
        deprecated_rule=deprecated_introspection_data,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name='introspection:reapply',
        check_str=SYSTEM_ADMIN,
        description='Reapply introspection on stored data',
        operations=[{'path': '/introspection/{node_id}/data/unprocessed',
                     'method': 'POST'}],
        deprecated_rule=deprecated_introspection_reapply,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
]

rule_policies = [
    policy.DocumentedRuleDefault(
        name='introspection:rule:get',
        check_str=SYSTEM_ADMIN,
        description='Get introspection rule(s)',
        operations=[{'path': '/rules', 'method': 'GET'},
                    {'path': '/rules/{rule_id}', 'method': 'GET'}],
        deprecated_rule=deprecated_introspection_rule_get,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name='introspection:rule:delete',
        check_str=SYSTEM_ADMIN,
        description='Delete introspection rule(s)',
        operations=[{'path': '/rules', 'method': 'DELETE'},
                    {'path': '/rules/{rule_id}', 'method': 'DELETE'}],
        deprecated_rule=deprecated_introspection_rule_delete,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
    policy.DocumentedRuleDefault(
        name='introspection:rule:create',
        check_str=SYSTEM_ADMIN,
        description='Create introspection rule',
        operations=[{'path': '/rules', 'method': 'POST'}],
        deprecated_rule=deprecated_introspection_rule_create,
        deprecated_reason=deprecated_node_reason,
        deprecated_since=versionutils.deprecated.WALLABY
    ),
]


def list_policies():
    """Get list of all policies defined in code.

    Used to register them all at runtime,
    and by oslo-config-generator to generate sample policy files.
    """
    policies = itertools.chain(
        default_policies,
        api_version_policies,
        introspection_policies,
        rule_policies)
    return policies


@lockutils.synchronized('policy_enforcer')
def init_enforcer(policy_file=None, rules=None,
                  default_rule=None, use_conf=True):
    """Synchronously initializes the policy enforcer

       :param policy_file: Custom policy file to use, if none is specified,
                           `CONF.oslo_policy.policy_file` will be used.
       :param rules: Default dictionary / Rules to use. It will be
                     considered just in the first instantiation.
       :param default_rule: Default rule to use,
                            CONF.oslo_policy.policy_default_rule will
                            be used if none is specified.
       :param use_conf: Whether to load rules from config file.
    """
    global _ENFORCER

    if _ENFORCER:
        return
    _ENFORCER = policy.Enforcer(
        CONF, policy_file=policy_file,
        rules=rules,
        default_rule=default_rule,
        use_conf=use_conf)
    _ENFORCER.register_defaults(list_policies())


def get_enforcer():
    """Provides access to the single instance of Policy enforcer."""
    if not _ENFORCER:
        init_enforcer()
    return _ENFORCER


def get_oslo_policy_enforcer():
    """Get the enforcer instance to generate policy files.

    This method is for use by oslopolicy CLI scripts.
    Those scripts need the 'output-file' and 'namespace' options,
    but having those in sys.argv means loading the inspector config options
    will fail as those are not expected to be present.
    So we pass in an arg list with those stripped out.
    """

    conf_args = []
    # Start at 1 because cfg.CONF expects the equivalent of sys.argv[1:]
    i = 1
    while i < len(sys.argv):
        if sys.argv[i].strip('-') in ['namespace', 'output-file']:
            # e.g. --namespace <somestring>
            i += 2
            continue
        conf_args.append(sys.argv[i])
        i += 1

    cfg.CONF(conf_args, project='ironic-inspector')

    return get_enforcer()


def authorize(rule, target, creds, *args, **kwargs):
    """A shortcut for policy.Enforcer.authorize()

    Checks authorization of a rule against the target and credentials, and
    raises an exception if the rule is not defined.
    args and kwargs are passed directly to oslo.policy Enforcer.authorize
    Always returns True if CONF.auth_strategy != keystone.

    :param rule: name of a registered oslo.policy rule
    :param target: dict-like structure to check rule against
    :param creds: dict of policy values from request
    :returns: True if request is authorized against given policy,
              False otherwise
    :raises: oslo_policy.policy.PolicyNotRegistered if supplied policy
             is not registered in oslo_policy
    """
    if CONF.auth_strategy != 'keystone':
        return True
    enforcer = get_enforcer()
    rule = CONF.oslo_policy.policy_default_rule if rule is None else rule
    return enforcer.authorize(rule, target, creds, *args, **kwargs)
