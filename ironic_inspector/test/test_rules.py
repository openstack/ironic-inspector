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

"""Tests for introspection rules."""

import mock

from ironic_inspector import db
from ironic_inspector import node_cache
from ironic_inspector.plugins import base as plugins_base
from ironic_inspector import rules
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


class BaseTest(test_base.BaseTest):
    def setUp(self):
        super(BaseTest, self).setUp()
        self.uuid = 'uuid'
        self.conditions_json = [
            {'op': 'eq', 'field': 'memory_mb', 'value': 1024},
            {'op': 'eq', 'field': 'local_gb', 'value': 60},
        ]
        self.actions_json = [
            {'action': 'fail', 'message': 'boom!'}
        ]

        self.data = {
            'memory_mb': 1024,
            'local_gb': 42,
        }
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=42)


class TestCreateRule(BaseTest):
    def test_only_actions(self):
        rule = rules.create([], self.actions_json)
        rule_json = rule.as_dict()

        self.assertTrue(rule_json.pop('uuid'))
        self.assertEqual({'description': None,
                          'conditions': [],
                          'actions': self.actions_json},
                         rule_json)

    def test_duplicate_uuid(self):
        rules.create([], self.actions_json, uuid=self.uuid)
        self.assertRaisesRegexp(utils.Error, 'already exists',
                                rules.create, [], self.actions_json,
                                uuid=self.uuid)

    def test_with_conditions(self):
        rule = rules.create(self.conditions_json, self.actions_json)
        rule_json = rule.as_dict()

        self.assertTrue(rule_json.pop('uuid'))
        self.assertEqual({'description': None,
                          'conditions': self.conditions_json,
                          'actions': self.actions_json},
                         rule_json)

    def test_invalid_condition(self):
        del self.conditions_json[0]['op']

        self.assertRaisesRegexp(utils.Error,
                                'Validation failed for conditions',
                                rules.create,
                                self.conditions_json, self.actions_json)

        self.conditions_json[0]['op'] = 'foobar'

        self.assertRaisesRegexp(utils.Error,
                                'Validation failed for conditions',
                                rules.create,
                                self.conditions_json, self.actions_json)

    def test_invalid_condition_field(self):
        self.conditions_json[0]['field'] = '!*!'

        self.assertRaisesRegexp(utils.Error,
                                'Unable to parse field JSON path',
                                rules.create,
                                self.conditions_json, self.actions_json)

    def test_invalid_condition_parameters(self):
        self.conditions_json[0]['foo'] = 'bar'

        self.assertRaisesRegexp(utils.Error,
                                'Invalid parameters for operator',
                                rules.create,
                                self.conditions_json, self.actions_json)

    def test_no_actions(self):
        self.assertRaisesRegexp(utils.Error,
                                'Validation failed for actions',
                                rules.create,
                                self.conditions_json, [])

    def test_invalid_action(self):
        del self.actions_json[0]['action']

        self.assertRaisesRegexp(utils.Error,
                                'Validation failed for actions',
                                rules.create,
                                self.conditions_json, self.actions_json)

        self.actions_json[0]['action'] = 'foobar'

        self.assertRaisesRegexp(utils.Error,
                                'Validation failed for actions',
                                rules.create,
                                self.conditions_json, self.actions_json)

    def test_invalid_action_parameters(self):
        self.actions_json[0]['foo'] = 'bar'

        self.assertRaisesRegexp(utils.Error,
                                'Invalid parameters for action',
                                rules.create,
                                self.conditions_json, self.actions_json)


class TestGetRule(BaseTest):
    def setUp(self):
        super(TestGetRule, self).setUp()
        rules.create(self.conditions_json, self.actions_json, uuid=self.uuid)

    def test_get(self):
        rule_json = rules.get(self.uuid).as_dict()

        self.assertTrue(rule_json.pop(self.uuid))
        self.assertEqual({'description': None,
                          'conditions': self.conditions_json,
                          'actions': self.actions_json},
                         rule_json)

    def test_not_found(self):
        self.assertRaises(utils.Error, rules.get, 'foobar')

    def test_get_all(self):
        rules.create(self.conditions_json, self.actions_json, uuid='uuid2')
        self.assertEqual([self.uuid, 'uuid2'],
                         [r.as_dict()['uuid'] for r in rules.get_all()])


class TestDeleteRule(BaseTest):
    def setUp(self):
        super(TestDeleteRule, self).setUp()
        self.uuid2 = self.uuid + '-2'
        rules.create(self.conditions_json, self.actions_json, uuid=self.uuid)
        rules.create(self.conditions_json, self.actions_json, uuid=self.uuid2)

    def test_delete(self):
        rules.delete(self.uuid)

        self.assertEqual([(self.uuid2,)], db.model_query(db.Rule.uuid).all())
        self.assertFalse(db.model_query(db.RuleCondition)
                         .filter_by(rule=self.uuid).all())
        self.assertFalse(db.model_query(db.RuleAction)
                         .filter_by(rule=self.uuid).all())

    def test_delete_non_existing(self):
        self.assertRaises(utils.Error, rules.delete, 'foo')

    def test_delete_all(self):
        rules.delete_all()

        self.assertFalse(db.model_query(db.Rule).all())
        self.assertFalse(db.model_query(db.RuleCondition).all())
        self.assertFalse(db.model_query(db.RuleAction).all())


@mock.patch.object(plugins_base, 'rule_conditions_manager', autospec=True)
class TestCheckConditions(BaseTest):
    def setUp(self):
        super(TestCheckConditions, self).setUp()

        self.rule = rules.create(conditions_json=self.conditions_json,
                                 actions_json=self.actions_json)
        self.cond_mock = mock.Mock(spec=plugins_base.RuleConditionPlugin)
        self.cond_mock.ALLOW_NONE = False
        self.ext_mock = mock.Mock(spec=['obj'], obj=self.cond_mock)

    def test_ok(self, mock_ext_mgr):
        mock_ext_mgr.return_value.__getitem__.return_value = self.ext_mock
        self.cond_mock.check.return_value = True

        res = self.rule.check_conditions(self.node_info, self.data)

        self.cond_mock.check.assert_any_call(self.node_info, 1024,
                                             {'value': 1024})
        self.cond_mock.check.assert_any_call(self.node_info, 42,
                                             {'value': 60})
        self.assertEqual(len(self.conditions_json),
                         self.cond_mock.check.call_count)
        self.assertTrue(res)

    def test_no_field(self, mock_ext_mgr):
        mock_ext_mgr.return_value.__getitem__.return_value = self.ext_mock
        self.cond_mock.check.return_value = True
        del self.data['local_gb']

        res = self.rule.check_conditions(self.node_info, self.data)

        self.cond_mock.check.assert_called_once_with(self.node_info, 1024,
                                                     {'value': 1024})
        self.assertFalse(res)

    def test_no_field_none_allowed(self, mock_ext_mgr):
        mock_ext_mgr.return_value.__getitem__.return_value = self.ext_mock
        self.cond_mock.ALLOW_NONE = True
        self.cond_mock.check.return_value = True
        del self.data['local_gb']

        res = self.rule.check_conditions(self.node_info, self.data)

        self.cond_mock.check.assert_any_call(self.node_info, 1024,
                                             {'value': 1024})
        self.cond_mock.check.assert_any_call(self.node_info, None,
                                             {'value': 60})
        self.assertEqual(len(self.conditions_json),
                         self.cond_mock.check.call_count)
        self.assertTrue(res)

    def test_fail(self, mock_ext_mgr):
        mock_ext_mgr.return_value.__getitem__.return_value = self.ext_mock
        self.cond_mock.check.return_value = False

        res = self.rule.check_conditions(self.node_info, self.data)

        self.cond_mock.check.assert_called_once_with(self.node_info, 1024,
                                                     {'value': 1024})
        self.assertFalse(res)


class TestCheckConditionsMultiple(BaseTest):
    def setUp(self):
        super(TestCheckConditionsMultiple, self).setUp()

        self.conditions_json = [
            {'op': 'eq', 'field': 'interfaces[*].ip', 'value': '1.2.3.4'}
        ]

    def _build_data(self, ips):
        return {
            'interfaces': [
                {'ip': ip} for ip in ips
            ]
        }

    def test_default(self):
        rule = rules.create(conditions_json=self.conditions_json,
                            actions_json=self.actions_json)
        data_set = [
            (['1.1.1.1', '1.2.3.4', '1.3.2.2'], True),
            (['1.2.3.4'], True),
            (['1.1.1.1', '1.3.2.2'], False),
            (['1.2.3.4', '1.3.2.2'], True),
        ]
        for ips, result in data_set:
            data = self._build_data(ips)
            self.assertIs(result, rule.check_conditions(self.node_info, data),
                          data)

    def test_any(self):
        self.conditions_json[0]['multiple'] = 'any'
        rule = rules.create(conditions_json=self.conditions_json,
                            actions_json=self.actions_json)
        data_set = [
            (['1.1.1.1', '1.2.3.4', '1.3.2.2'], True),
            (['1.2.3.4'], True),
            (['1.1.1.1', '1.3.2.2'], False),
            (['1.2.3.4', '1.3.2.2'], True),
        ]
        for ips, result in data_set:
            data = self._build_data(ips)
            self.assertIs(result, rule.check_conditions(self.node_info, data),
                          data)

    def test_all(self):
        self.conditions_json[0]['multiple'] = 'all'
        rule = rules.create(conditions_json=self.conditions_json,
                            actions_json=self.actions_json)
        data_set = [
            (['1.1.1.1', '1.2.3.4', '1.3.2.2'], False),
            (['1.2.3.4'], True),
            (['1.1.1.1', '1.3.2.2'], False),
            (['1.2.3.4', '1.3.2.2'], False),
        ]
        for ips, result in data_set:
            data = self._build_data(ips)
            self.assertIs(result, rule.check_conditions(self.node_info, data),
                          data)

    def test_first(self):
        self.conditions_json[0]['multiple'] = 'first'
        rule = rules.create(conditions_json=self.conditions_json,
                            actions_json=self.actions_json)
        data_set = [
            (['1.1.1.1', '1.2.3.4', '1.3.2.2'], False),
            (['1.2.3.4'], True),
            (['1.1.1.1', '1.3.2.2'], False),
            (['1.2.3.4', '1.3.2.2'], True),
        ]
        for ips, result in data_set:
            data = self._build_data(ips)
            self.assertIs(result, rule.check_conditions(self.node_info, data),
                          data)


@mock.patch.object(plugins_base, 'rule_actions_manager', autospec=True)
class TestApplyActions(BaseTest):
    def setUp(self):
        super(TestApplyActions, self).setUp()
        self.actions_json.append({'action': 'example'})

        self.rule = rules.create(conditions_json=self.conditions_json,
                                 actions_json=self.actions_json)
        self.act_mock = mock.Mock(spec=plugins_base.RuleActionPlugin)
        self.ext_mock = mock.Mock(spec=['obj'], obj=self.act_mock)

    def test_apply(self, mock_ext_mgr):
        mock_ext_mgr.return_value.__getitem__.return_value = self.ext_mock

        self.rule.apply_actions(self.node_info)

        self.act_mock.apply.assert_any_call(self.node_info,
                                            {'message': 'boom!'})
        self.act_mock.apply.assert_any_call(self.node_info, {})
        self.assertEqual(len(self.actions_json),
                         self.act_mock.apply.call_count)
        self.assertFalse(self.act_mock.rollback.called)

    def test_rollback(self, mock_ext_mgr):
        mock_ext_mgr.return_value.__getitem__.return_value = self.ext_mock

        self.rule.apply_actions(self.node_info, rollback=True)

        self.act_mock.rollback.assert_any_call(self.node_info,
                                               {'message': 'boom!'})
        self.act_mock.rollback.assert_any_call(self.node_info, {})
        self.assertEqual(len(self.actions_json),
                         self.act_mock.rollback.call_count)
        self.assertFalse(self.act_mock.apply.called)


@mock.patch.object(rules, 'get_all', autospec=True)
class TestApply(BaseTest):
    def setUp(self):
        super(TestApply, self).setUp()
        self.rules = [mock.Mock(spec=rules.IntrospectionRule),
                      mock.Mock(spec=rules.IntrospectionRule)]

    def test_no_rules(self, mock_get_all):
        mock_get_all.return_value = []

        rules.apply(self.node_info, self.data)

    def test_no_actions(self, mock_get_all):
        mock_get_all.return_value = self.rules
        for idx, rule in enumerate(self.rules):
            rule.check_conditions.return_value = not bool(idx)

        rules.apply(self.node_info, self.data)

        for idx, rule in enumerate(self.rules):
            rule.check_conditions.assert_called_once_with(self.node_info,
                                                          self.data)
            rule.apply_actions.assert_called_once_with(
                self.node_info, rollback=bool(idx))

    def test_actions(self, mock_get_all):
        mock_get_all.return_value = self.rules
        for idx, rule in enumerate(self.rules):
            rule.check_conditions.return_value = not bool(idx)

        rules.apply(self.node_info, self.data)

        for idx, rule in enumerate(self.rules):
            rule.check_conditions.assert_called_once_with(self.node_info,
                                                          self.data)
            rule.apply_actions.assert_called_once_with(
                self.node_info, rollback=bool(idx))

    def test_no_rollback(self, mock_get_all):
        mock_get_all.return_value = self.rules
        for rule in self.rules:
            rule.check_conditions.return_value = True

        rules.apply(self.node_info, self.data)

        for rule in self.rules:
            rule.check_conditions.assert_called_once_with(self.node_info,
                                                          self.data)
            rule.apply_actions.assert_called_once_with(
                self.node_info, rollback=False)

    def test_only_rollback(self, mock_get_all):
        mock_get_all.return_value = self.rules
        for rule in self.rules:
            rule.check_conditions.return_value = False

        rules.apply(self.node_info, self.data)

        for rule in self.rules:
            rule.check_conditions.assert_called_once_with(self.node_info,
                                                          self.data)
            rule.apply_actions.assert_called_once_with(
                self.node_info, rollback=True)
