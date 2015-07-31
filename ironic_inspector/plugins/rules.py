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

"""Standard plugins for rules API."""

import operator

from oslo_log import log

from ironic_inspector.plugins import base
from ironic_inspector import utils


LOG = log.getLogger(__name__)


def coerce(value, expected):
    if isinstance(expected, float):
        return float(value)
    elif isinstance(expected, int):
        return int(value)
    else:
        return value


class SimpleCondition(base.RuleConditionPlugin):
    op = None

    def check(self, node_info, field, params, **kwargs):
        value = params['value']
        return self.op(coerce(field, value), value)


class EqCondition(SimpleCondition):
    op = operator.eq


class LtCondition(SimpleCondition):
    op = operator.lt


class GtCondition(SimpleCondition):
    op = operator.gt


class LeCondition(SimpleCondition):
    op = operator.le


class GeCondition(SimpleCondition):
    op = operator.ge


class NeCondition(SimpleCondition):
    op = operator.ne


class FailAction(base.RuleActionPlugin):
    REQUIRED_PARAMS = {'message'}

    def apply(self, node_info, params, **kwargs):
        raise utils.Error(params['message'])


class SetAttributeAction(base.RuleActionPlugin):
    REQUIRED_PARAMS = {'path', 'value'}
    # TODO(dtantsur): proper validation of path

    def apply(self, node_info, params, **kwargs):
        node_info.patch([{'op': 'add', 'path': params['path'],
                          'value': params['value']}])

    def rollback(self, node_info, params, **kwargs):
        try:
            node_info.get_by_path(params['path'])
        except KeyError:
            LOG.debug('Field %(path)s was not set on node %(node)s, '
                      'no need for rollback',
                      {'path': params['path'], 'node': node_info.uuid})
            return

        node_info.patch([{'op': 'remove', 'path': params['path']}])
