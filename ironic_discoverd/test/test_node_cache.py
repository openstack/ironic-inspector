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

import os
import tempfile
import time
import unittest

import mock

from ironic_discoverd import conf
from ironic_discoverd import node_cache
from ironic_discoverd.test import base as test_base
from ironic_discoverd import utils


class TestNodeCache(test_base.NodeTest):
    def test_add_node(self):
        # Ensure previous node information is cleared
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.execute("insert into nodes(uuid) values('uuid2')")
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', self.uuid))

        res = node_cache.add_node(self.node.uuid, mac=self.macs,
                                  bmc_address='1.2.3.4', foo=None)
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 60)

        res = self.db.execute("select uuid, started_at "
                              "from nodes order by uuid").fetchall()
        self.assertEqual(['uuid', 'uuid2'], [t[0] for t in res])
        self.assertTrue(time.time() - 60 < res[0][1] < time.time() + 60)

        res = self.db.execute("select name, value, uuid from attributes "
                              "order by name, value").fetchall()
        self.assertEqual([('bmc_address', '1.2.3.4', self.uuid),
                          ('mac', self.macs[0], self.uuid),
                          ('mac', self.macs[1], self.uuid)],
                         [tuple(row) for row in res])

    def test_add_node_duplicate_mac(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            ('another-uuid',))
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', 'another-uuid'))

        self.assertRaises(utils.Error,
                          node_cache.add_node,
                          self.node.uuid, mac=['11:22:11:22:11:22'])

    def test_active_macs(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.executemany("insert into attributes(name, value, uuid) "
                                "values(?, ?, ?)",
                                [('mac', '11:22:11:22:11:22', self.uuid),
                                 ('mac', '22:11:22:11:22:11', self.uuid)])
        self.assertEqual({'11:22:11:22:11:22', '22:11:22:11:22:11'},
                         node_cache.active_macs())


class TestNodeCacheFind(test_base.NodeTest):
    def setUp(self):
        super(TestNodeCacheFind, self).setUp()
        self.macs2 = ['00:00:00:00:00:00']
        node_cache.add_node(self.uuid,
                            bmc_address='1.2.3.4',
                            mac=self.macs)

    def test_no_data(self):
        self.assertRaises(utils.Error, node_cache.find_node)
        self.assertRaises(utils.Error, node_cache.find_node, mac=[])

    def test_bmc(self):
        res = node_cache.find_node(bmc_address='1.2.3.4')
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 1)

    def test_macs(self):
        res = node_cache.find_node(mac=['11:22:33:33:33:33', self.macs[1]])
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 1)

    def test_macs_not_found(self):
        self.assertRaises(utils.Error, node_cache.find_node,
                          mac=['11:22:33:33:33:33',
                               '66:66:44:33:22:11'])

    def test_macs_multiple_found(self):
        node_cache.add_node('uuid2', mac=self.macs2)
        self.assertRaises(utils.Error, node_cache.find_node,
                          mac=[self.macs[0], self.macs2[0]])

    def test_both(self):
        res = node_cache.find_node(bmc_address='1.2.3.4',
                                   mac=self.macs)
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 1)

    def test_inconsistency(self):
        with self.db:
            self.db.execute('delete from nodes where uuid=?', (self.uuid,))
        self.assertRaises(utils.Error, node_cache.find_node,
                          bmc_address='1.2.3.4')

    def test_already_finished(self):
        with self.db:
            self.db.execute('update nodes set finished_at=42.0 where uuid=?',
                            (self.uuid,))
        self.assertRaises(utils.Error, node_cache.find_node,
                          bmc_address='1.2.3.4')


class TestNodeCacheCleanUp(test_base.NodeTest):
    def setUp(self):
        super(TestNodeCacheCleanUp, self).setUp()
        self.started_at = 100.0
        with self.db:
            self.db.execute('insert into nodes(uuid, started_at) '
                            'values(?, ?)', (self.uuid, self.started_at))
            self.db.executemany('insert into attributes(name, value, uuid) '
                                'values(?, ?, ?)',
                                [('mac', v, self.uuid) for v in self.macs])
            self.db.execute('insert into options(uuid, name, value) '
                            'values(?, ?, ?)', (self.uuid, 'foo', 'bar'))

    def test_no_timeout(self):
        conf.CONF.set('discoverd', 'timeout', '0')

        self.assertFalse(node_cache.clean_up())

        res = [tuple(row) for row in self.db.execute(
            'select finished_at, error from nodes').fetchall()]
        self.assertEqual([(None, None)], res)
        self.assertEqual(len(self.macs), len(self.db.execute(
            'select * from attributes').fetchall()))
        self.assertEqual(1, len(self.db.execute(
            'select * from options').fetchall()))

    @mock.patch.object(time, 'time')
    def test_ok(self, time_mock):
        time_mock.return_value = 1000

        self.assertFalse(node_cache.clean_up())

        res = [tuple(row) for row in self.db.execute(
            'select finished_at, error from nodes').fetchall()]
        self.assertEqual([(None, None)], res)
        self.assertEqual(len(self.macs), len(self.db.execute(
            'select * from attributes').fetchall()))
        self.assertEqual(1, len(self.db.execute(
            'select * from options').fetchall()))

    @mock.patch.object(time, 'time')
    def test_timeout(self, time_mock):
        # Add a finished node to confirm we don't try to timeout it
        with self.db:
            self.db.execute('insert into nodes(uuid, started_at, finished_at) '
                            'values(?, ?, ?)', (self.uuid + '1',
                                                self.started_at,
                                                self.started_at + 60))
        conf.CONF.set('discoverd', 'timeout', '99')
        time_mock.return_value = self.started_at + 100

        self.assertEqual([self.uuid], node_cache.clean_up())

        res = [tuple(row) for row in self.db.execute(
            'select finished_at, error from nodes order by uuid').fetchall()]
        self.assertEqual([(self.started_at + 100, 'Introspection timeout'),
                          (self.started_at + 60, None)],
                         res)
        self.assertEqual([], self.db.execute(
            'select * from attributes').fetchall())
        self.assertEqual([], self.db.execute(
            'select * from options').fetchall())

    def test_old_status(self):
        conf.CONF.set('discoverd', 'node_status_keep_time', '42')
        with self.db:
            self.db.execute('update nodes set finished_at=?',
                            (time.time() - 100,))

        self.assertEqual([], node_cache.clean_up())

        self.assertEqual([], self.db.execute(
            'select * from nodes').fetchall())


class TestNodeCacheGetNode(test_base.NodeTest):
    def test_ok(self):
        started_at = time.time() - 42
        with self.db:
            self.db.execute('insert into nodes(uuid, started_at) '
                            'values(?, ?)', (self.uuid, started_at))
        info = node_cache.get_node(self.uuid)

        self.assertEqual(self.uuid, info.uuid)
        self.assertEqual(started_at, info.started_at)
        self.assertIsNone(info.finished_at)
        self.assertIsNone(info.error)

    def test_not_found(self):
        self.assertRaises(utils.Error, node_cache.get_node, 'foo')


@mock.patch.object(time, 'time', lambda: 42.0)
class TestNodeInfoFinished(test_base.NodeTest):
    def setUp(self):
        super(TestNodeInfoFinished, self).setUp()
        node_cache.add_node(self.uuid,
                            bmc_address='1.2.3.4',
                            mac=self.macs)
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=3.14)
        with self.db:
            self.db.execute('insert into options(uuid, name, value) '
                            'values(?, ?, ?)', (self.uuid, 'foo', 'bar'))

    def test_success(self):
        self.node_info.finished()

        self.assertEqual((42.0, None), tuple(self.db.execute(
            'select finished_at, error from nodes').fetchone()))
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())
        self.assertEqual([], self.db.execute(
            "select * from options").fetchall())

    def test_error(self):
        self.node_info.finished(error='boom')

        self.assertEqual((42.0, 'boom'), tuple(self.db.execute(
            'select finished_at, error from nodes').fetchone()))
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())
        self.assertEqual([], self.db.execute(
            "select * from options").fetchall())


class TestInit(unittest.TestCase):
    def setUp(self):
        super(TestInit, self).setUp()
        conf.init_conf()
        conf.CONF.add_section('discoverd')
        node_cache._DB_NAME = None

    def test_ok(self):
        with tempfile.NamedTemporaryFile() as db_file:
            conf.CONF.set('discoverd', 'database', db_file.name)
            node_cache.init()

            self.assertIsNotNone(node_cache._DB_NAME)
            # Verify that table exists
            node_cache._db().execute("select * from nodes")

    def test_create_dir(self):
        temp = tempfile.mkdtemp()
        conf.CONF.set('discoverd', 'database',
                      os.path.join(temp, 'dir', 'file'))
        node_cache.init()

    def test_no_database(self):
        self.assertRaises(SystemExit, node_cache.init)


class TestNodeInfoOptions(test_base.NodeTest):
    def setUp(self):
        super(TestNodeInfoOptions, self).setUp()
        node_cache.add_node(self.uuid,
                            bmc_address='1.2.3.4',
                            mac=self.macs)
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=3.14)
        with self.db:
            self.db.execute('insert into options(uuid, name, value) '
                            'values(?, ?, ?)', (self.uuid, 'foo', '"bar"'))

    def test_get(self):
        self.assertEqual({'foo': 'bar'}, self.node_info.options)
        # should be cached
        self.assertIs(self.node_info.options, self.node_info.options)

    def test_set(self):
        data = {'s': 'value', 'b': True, 'i': 42}
        self.node_info.set_option('name', data)
        self.assertEqual(data, self.node_info.options['name'])

        new = node_cache.NodeInfo(uuid=self.uuid, started_at=3.14)
        self.assertEqual(data, new.options['name'])
