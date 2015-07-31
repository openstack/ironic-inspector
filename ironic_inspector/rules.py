# Copyright 2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Support for introspection rules."""

import jsonpath_rw as jsonpath
import jsonschema
from oslo_db import exception as db_exc
from oslo_log import log
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import orm

from ironic_inspector.common.i18n import _, _LE, _LI
from ironic_inspector import db
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector import utils


LOG = log.getLogger(__name__)
_CONDITIONS_SCHEMA = None
_ACTIONS_SCHEMA = None


def conditions_schema():
    global _CONDITIONS_SCHEMA
    if _CONDITIONS_SCHEMA is None:
        condition_plugins = [x.name for x in
                             plugins_base.rule_conditions_manager()]
        _CONDITIONS_SCHEMA = {
            "title": "Inspector rule conditions schema",
            "type": "array",
            # we can have rules that always apply
            "minItems": 0,
            "items": {
                "type": "object",
                # field might become optional in the future, but not right now
                "required": ["op", "field"],
                "properties": {
                    "op": {
                        "description": "condition operator",
                        "enum": condition_plugins
                    },
                    "field": {
                        "description": "JSON path to field for matching",
                        "type": "string"
                    },
                    "multiple": {
                        "description": "how to treat multiple values",
                        "enum": ["all", "any", "first"]
                    },
                },
                # other properties are validated by plugins
                "additionalProperties": True
            }
        }

    return _CONDITIONS_SCHEMA


def actions_schema():
    global _ACTIONS_SCHEMA
    if _ACTIONS_SCHEMA is None:
        action_plugins = [x.name for x in
                          plugins_base.rule_actions_manager()]
        _ACTIONS_SCHEMA = {
            "title": "Inspector rule actions schema",
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {
                        "description": "action to take",
                        "enum": action_plugins
                    },
                },
                # other properties are validated by plugins
                "additionalProperties": True
            }
        }

    return _ACTIONS_SCHEMA


class IntrospectionRule(object):
    """High-level class representing an introspection rule."""

    def __init__(self, uuid, conditions, actions, description):
        """Create rule object from database data."""
        self._uuid = uuid
        self._conditions = conditions
        self._actions = actions
        self._description = description

    def as_dict(self, short=False):
        result = {
            'uuid': self._uuid,
            'description': self._description,
        }

        if not short:
            result['conditions'] = [c.as_dict() for c in self._conditions]
            result['actions'] = [a.as_dict() for a in self._actions]

        return result

    @property
    def description(self):
        return self._description or self._uuid

    def check_conditions(self, node_info, data):
        """Check if conditions are true for a given node.

        :param node_info: a NodeInfo object
        :param data: introspection data
        :returns: True if conditions match, otherwise False
        """
        LOG.debug('Checking rule "%(descr)s" on node %(uuid)s',
                  {'descr': self.description, 'uuid': node_info.uuid})
        ext_mgr = plugins_base.rule_conditions_manager()
        for cond in self._conditions:
            field_values = jsonpath.parse(cond.field).find(data)
            field_values = [x.value for x in field_values]
            cond_ext = ext_mgr[cond.op].obj

            if not field_values:
                if cond_ext.ALLOW_NONE:
                    LOG.debug('Field with JSON path %(path)s was not found in '
                              'data for node %(uuid)s',
                              {'path': cond.field, 'uuid': node_info.uuid})
                    field_values = [None]
                else:
                    LOG.info(_LI('Field with JSON path %(path)s was not found '
                                 'in data for node %(uuid)s, rule "%(rule)s" '
                                 'will not be applied'),
                             {'path': cond.field, 'uuid': node_info.uuid,
                              'rule': self.description})
                    return False

            for value in field_values:
                result = cond_ext.check(node_info, value, cond.params)
                if (cond.multiple == 'first'
                        or (cond.multiple == 'all' and not result)
                        or (cond.multiple == 'any' and result)):
                    break

            if not result:
                LOG.info(_LI('Rule "%(rule)s" will not be applied to node '
                             '%(uuid)s: condition %(field)s %(op)s %(params)s '
                             'failed'),
                         {'rule': self.description, 'uuid': node_info.uuid,
                          'field': cond.field, 'op': cond.op,
                          'params': cond.params})
                return False

        LOG.info(_LI('Rule "%(rule)s" will be applied to node %(uuid)s'),
                 {'rule': self.description, 'uuid': node_info.uuid})
        return True

    def apply_actions(self, node_info, rollback=False):
        """Run actions on a node.

        :param node_info: NodeInfo instance
        :param rollback: if True, rollback actions are executed
        """
        if rollback:
            method = 'rollback'
        else:
            method = 'apply'

        LOG.debug('Running %(what)s actions for rule "%(rule)s" '
                  'on node %(node)s',
                  {'what': method, 'rule': self.description,
                   'node': node_info.uuid})

        ext_mgr = plugins_base.rule_actions_manager()
        for act in self._actions:
            LOG.debug('Running %(what)s action `%(action)s %(params)s` for '
                      'node %(node)s',
                      {'action': act.action, 'params': act.params,
                       'node': node_info.uuid, 'what': method})
            ext = ext_mgr[act.action].obj
            getattr(ext, method)(node_info, act.params)

        LOG.debug('Successfully applied %(what)s to node %(node)s',
                  {'what': 'rollback actions' if rollback else 'actions',
                   'node': node_info.uuid})


def create(conditions_json, actions_json, uuid=None,
           description=None):
    """Create a new rule in database.

    :param conditions_json: list of dicts with the following keys:
                            * op - operator
                            * field - JSON path to field to compare
                            Other keys are stored as is.
    :param actions_json: list of dicts with the following keys:
                         * action - action type
                         Other keys are stored as is.
    :param uuid: rule UUID, will be generated if empty
    :param description: human-readable rule description
    :returns: new IntrospectionRule object
    :raises: utils.Error on failure
    """
    uuid = uuid or uuidutils.generate_uuid()
    LOG.debug('Creating rule %(uuid)s with description "%(descr)s", '
              'conditions %(conditions)s and actions %(actions)s',
              {'uuid': uuid, 'descr': description,
               'conditions': conditions_json, 'actions': actions_json})

    try:
        jsonschema.validate(conditions_json, conditions_schema())
    except jsonschema.ValidationError as exc:
        raise utils.Error(_('Validation failed for conditions: %s') % exc)

    try:
        jsonschema.validate(actions_json, actions_schema())
    except jsonschema.ValidationError as exc:
        raise utils.Error(_('Validation failed for actions: %s') % exc)

    cond_mgr = plugins_base.rule_conditions_manager()
    act_mgr = plugins_base.rule_actions_manager()

    conditions = []
    for cond_json in conditions_json:
        field = cond_json['field']
        try:
            jsonpath.parse(field)
        except Exception as exc:
            raise utils.Error(_('Unable to parse field JSON path %(field)s: '
                                '%(error)s') % {'field': field, 'error': exc})

        plugin = cond_mgr[cond_json['op']].obj
        params = {k: v for k, v in cond_json.items()
                  if k not in ('op', 'field', 'multiple')}
        try:
            plugin.validate(params)
        except ValueError as exc:
            raise utils.Error(_('Invalid parameters for operator %(op)s: '
                                '%(error)s') %
                              {'op': cond_json['op'], 'error': exc})

        conditions.append((cond_json['field'], cond_json['op'],
                           cond_json.get('multiple', 'any'), params))

    actions = []
    for action_json in actions_json:
        plugin = act_mgr[action_json['action']].obj
        params = {k: v for k, v in action_json.items() if k != 'action'}
        try:
            plugin.validate(params)
        except ValueError as exc:
            raise utils.Error(_('Invalid parameters for action %(act)s: '
                                '%(error)s') %
                              {'act': action_json['action'], 'error': exc})

        actions.append((action_json['action'], params))

    try:
        with db.ensure_transaction() as session:
            rule = db.Rule(uuid=uuid, description=description,
                           disabled=False, created_at=timeutils.utcnow())

            for field, op, multiple, params in conditions:
                rule.conditions.append(db.RuleCondition(op=op, field=field,
                                                        multiple=multiple,
                                                        params=params))

            for action, params in actions:
                rule.actions.append(db.RuleAction(action=action,
                                                  params=params))

            rule.save(session)
    except db_exc.DBDuplicateEntry as exc:
        LOG.error(_LE('Database integrity error %s when '
                      'creating a rule'), exc)
        raise utils.Error(_('Rule with UUID %s already exists') % uuid,
                          code=409)

    LOG.info(_LI('Created rule %(uuid)s with description "%(descr)s"'),
             {'uuid': uuid, 'descr': description})
    return IntrospectionRule(uuid=uuid,
                             conditions=rule.conditions,
                             actions=rule.actions,
                             description=description)


def get(uuid):
    """Get a rule by its UUID."""
    try:
        rule = db.model_query(db.Rule).filter_by(uuid=uuid).one()
    except orm.exc.NoResultFound:
        raise utils.Error(_('Rule %s was not found') % uuid, code=404)

    return IntrospectionRule(uuid=rule.uuid, actions=rule.actions,
                             conditions=rule.conditions,
                             description=rule.description)


def get_all():
    """List all rules."""
    query = db.model_query(db.Rule).order_by(db.Rule.created_at)
    return [IntrospectionRule(uuid=rule.uuid, actions=rule.actions,
                              conditions=rule.conditions,
                              description=rule.description)
            for rule in query]


def delete(uuid):
    """Delete a rule by its UUID."""
    with db.ensure_transaction() as session:
        db.model_query(db.RuleAction,
                       session=session).filter_by(rule=uuid).delete()
        db.model_query(db.RuleCondition,
                       session=session) .filter_by(rule=uuid).delete()
        count = (db.model_query(db.Rule, session=session)
                 .filter_by(uuid=uuid).delete())
        if not count:
            raise utils.Error(_('Rule %s was not found') % uuid, code=404)

    LOG.info(_LI('Introspection rule %s was deleted'), uuid)


def delete_all():
    """Delete all rules."""
    with db.ensure_transaction() as session:
        db.model_query(db.RuleAction, session=session).delete()
        db.model_query(db.RuleCondition, session=session).delete()
        db.model_query(db.Rule, session=session).delete()

    LOG.info(_LI('All introspection rules were deleted'))


def apply(node_info, data):
    """Apply rules to a node."""
    rules = get_all()
    if not rules:
        LOG.debug('No custom introspection rules to apply to node %s',
                  node_info.uuid)
        return

    LOG.debug('Applying custom introspection rules to node %s', node_info.uuid)

    to_rollback = []
    to_apply = []
    for rule in rules:
        if rule.check_conditions(node_info, data):
            to_apply.append(rule)
        else:
            to_rollback.append(rule)

    if to_rollback:
        LOG.debug('Running rollback actions on node %s', node_info.uuid)
        for rule in to_rollback:
            rule.apply_actions(node_info, rollback=True)
    else:
        LOG.debug('No rollback actions to apply on node %s', node_info.uuid)

    if to_apply:
        LOG.debug('Running actions on node %s', node_info.uuid)
        for rule in to_apply:
            rule.apply_actions(node_info, rollback=False)
    else:
        LOG.debug('No actions to apply on node %s', node_info.uuid)

    LOG.info(_LI('Successfully applied custom introspection rules to node %s'),
             node_info.uuid)
