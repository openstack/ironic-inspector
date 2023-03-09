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

import datetime

from oslo_utils import uuidutils

from ironic_inspector.db import api as db
from ironic_inspector import introspection_state as istate
from ironic_inspector.test import base as test_base
from ironic_inspector import utils


class TestDBAPI(test_base.NodeStateTest):
    def setUp(self):
        super(TestDBAPI, self).setUp()
        self.node2 = db.create_node(uuid=uuidutils.generate_uuid(),
                                    state=istate.States.processing,
                                    started_at=datetime.datetime(1, 1, 2),
                                    finished_at=None)
        self.attribute2 = ('fake_attr', 'boo')
        db.set_attribute(self.node2.uuid, *self.attribute2)

        self.option2 = ('fake_opt', 'foo')
        db.set_option(self.node2.uuid, *self.option2)

    def test_get_nodes(self):
        nodes = db.get_nodes()

        self.assertCountEqual([self.node2.uuid, self.uuid],
                              [node.uuid for node in nodes])

    def test_get_node_by_uuid(self):
        node = db.get_node(self.uuid)

        self.assertEqual(self.uuid, node.uuid)

    def test_get_node_by_uuid_not_found(self):
        self.assertRaises(
            utils.NodeNotFoundInDBError,
            db.get_node,
            uuidutils.generate_uuid())

    def test_get_node_by_uuid_version_mismatch(self):
        self.assertRaises(
            utils.NodeNotFoundInDBError,
            db.get_node,
            self.node2.uuid, version_id=123)

    def test_get_active_nodes(self):
        nodes = db.get_active_nodes()

        self.assertCountEqual([self.node2.uuid, self.uuid],
                              [node.uuid for node in nodes])

    def test_get_active_nodes_before(self):
        nodes = db.get_active_nodes(started_before=datetime.datetime(1, 1, 2))

        self.assertCountEqual([self.uuid],
                              [node.uuid for node in nodes])

    def test_list_nodes_by_attributes(self):
        attrs = db.list_nodes_by_attributes([self.attribute2])

        self.assertCountEqual([self.node2.uuid],
                              [attr.node_uuid for attr in attrs])

    def test_list_nodes_options_by_uuid(self):
        opts = db.list_nodes_options_by_uuid(self.node2.uuid)

        self.assertCountEqual([self.option2],
                              [(opt.name, opt.value) for opt in opts])

    def test_update_node(self):
        db.update_node(self.node2.uuid, state=istate.States.finished)

        node2 = db.get_node(self.node2.uuid)
        self.assertNotEqual(self.node2.state, node2.state)
        self.assertEqual(istate.States.finished, node2.state)

    def test_update_node_raises_exception(self):
        self.assertRaises(utils.NodeNotFoundInDBError,
                          db.update_node,
                          uuidutils.generate_uuid(),
                          error='foo')

    def tst_add_node(self):
        db.add_node(
            uuid=uuidutils.generate_uuid(),
            state=istate.States.finished)
        self.assertEqual(2, len(db.get_nodes()))

    def test_delete_node(self):
        db.delete_node(self.node2.uuid)

        self.assertRaises(utils.NodeNotFoundInDBError,
                          db.get_node,
                          self.node2.uuid)
        self.assertEqual([], db.get_attributes(node_uuid=self.node2.uuid))
        self.assertEqual([], db.get_options(uuid=self.node2.uuid))

    def test_delete_nodes(self):
        db.delete_nodes()

        self.assertEqual([], db.get_nodes())

    def test_delete_nodes_finished(self):
        db.delete_nodes(finished_until=datetime.datetime(4, 4, 4))

        self.assertCountEqual([self.uuid, self.node2.uuid],
                              [node.uuid for node in db.get_nodes()])

    def test_delete_options(self):
        db.delete_options(uuid=self.node2.uuid)

        self.assertEqual([], db.get_options(uuid=self.node2.uuid))

    def test_delete_attributes(self):
        node3 = db.create_node(uuid=uuidutils.generate_uuid(),
                               state=istate.States.finished,
                               started_at=datetime.datetime(1, 1, 3),
                               finished_at=datetime.datetime(1, 1, 4))
        attribute3 = ('fake_attr', 'boo')
        db.set_attribute(node3.uuid, *attribute3)

        db.delete_attributes(node3.uuid)
        self.assertEqual(
            [], db.get_attributes(node_uuid=node3.uuid))

    def test_store_introspection_data(self):
        node = db.create_node(uuid=uuidutils.generate_uuid(),
                              state=istate.States.finished,
                              started_at=datetime.datetime(1, 1, 3),
                              finished_at=datetime.datetime(1, 1, 4))
        db.store_introspection_data(node.uuid, {'foo': 'bar'})
        res = db.get_introspection_data(node.uuid)
        self.assertEqual(res['foo'], 'bar')
