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

"""Tests for introspection rules plugins."""

import mock

from ironic_inspector import node_cache
from ironic_inspector.plugins import rules as rules_plugins
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


TEST_SET = [(42, 42), ('42', 42), ('4.2', 4.2),
            (42, 41), ('42', 41), ('4.2', 4.0),
            (41, 42), ('41', 42), ('4.0', 4.2)]


class TestSimpleConditions(test_base.BaseTest):
    def test_validate(self):
        cond = rules_plugins.SimpleCondition()
        cond.validate({'value': 42})
        self.assertRaises(ValueError, cond.validate, {})

    def _test(self, cond, expected, value, ref):
        self.assertIs(expected, cond.check(None, value, {'value': ref}))

    def test_eq(self):
        cond = rules_plugins.EqCondition()
        for values, expected in zip(TEST_SET, [True] * 3 + [False] * 6):
            self._test(cond, expected, *values)
        self._test(cond, True, 'foo', 'foo')
        self._test(cond, False, 'foo', 'bar')

    def test_ne(self):
        cond = rules_plugins.NeCondition()
        for values, expected in zip(TEST_SET, [False] * 3 + [True] * 6):
            self._test(cond, expected, *values)
        self._test(cond, False, 'foo', 'foo')
        self._test(cond, True, 'foo', 'bar')

    def test_gt(self):
        cond = rules_plugins.GtCondition()
        for values, expected in zip(TEST_SET, [False] * 3 + [True] * 3
                                    + [False] * 3):
            self._test(cond, expected, *values)

    def test_ge(self):
        cond = rules_plugins.GeCondition()
        for values, expected in zip(TEST_SET, [True] * 6 + [False] * 3):
            self._test(cond, expected, *values)

    def test_le(self):
        cond = rules_plugins.LeCondition()
        for values, expected in zip(TEST_SET, [True] * 3 + [False] * 3
                                    + [True] * 3):
            self._test(cond, expected, *values)

    def test_lt(self):
        cond = rules_plugins.LtCondition()
        for values, expected in zip(TEST_SET, [False] * 6 + [True] * 3):
            self._test(cond, expected, *values)


class TestFailAction(test_base.BaseTest):
    act = rules_plugins.FailAction()

    def test_validate(self):
        self.act.validate({'message': 'boom'})
        self.assertRaises(ValueError, self.act.validate, {})

    def test_apply(self):
        self.assertRaisesRegexp(utils.Error, 'boom',
                                self.act.apply, None, {'message': 'boom'})


class TestSetAttributeAction(test_base.NodeTest):
    act = rules_plugins.SetAttributeAction()
    params = {'path': '/extra/value', 'value': 42}

    def test_validate(self):
        self.act.validate(self.params)
        self.assertRaises(ValueError, self.act.validate, {'value': 42})
        self.assertRaises(ValueError, self.act.validate,
                          {'path': '/extra/value'})

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_apply(self, mock_patch):
        self.act.apply(self.node_info, self.params)
        mock_patch.assert_called_once_with([{'op': 'add',
                                             'path': '/extra/value',
                                             'value': 42}])

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_rollback_with_existing(self, mock_patch):
        self.node.extra = {'value': 'value'}
        self.act.rollback(self.node_info, self.params)
        mock_patch.assert_called_once_with([{'op': 'remove',
                                             'path': '/extra/value'}])

    @mock.patch.object(node_cache.NodeInfo, 'patch')
    def test_rollback_no_existing(self, mock_patch):
        self.node.extra = {}
        self.act.rollback(self.node_info, self.params)
        self.assertFalse(mock_patch.called)
