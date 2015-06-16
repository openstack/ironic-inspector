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
from oslo_config import cfg

from ironic_inspector import node_cache
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = cfg.CONF


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
        self.assertEqual(['1a1a1a1a-2b2b-3c3c-4d4d-5e5e5e5e5e5e',
                          'uuid2'], [t[0] for t in res])
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

    def test_add_attribute(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
        node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=42)
        node_info.add_attribute('key', 'value')
        res = self.db.execute("select name, value, uuid from attributes "
                              "order by name, value").fetchall()
        self.assertEqual([('key', 'value', self.uuid)],
                         [tuple(row) for row in res])
        self.assertRaises(utils.Error, node_info.add_attribute,
                          'key', 'value')


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
        CONF.set_override('timeout', 0)

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
        CONF.set_override('timeout', 99)
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
        CONF.set_override('node_status_keep_time', 42)
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
        node_cache._DB_NAME = None

    def test_ok(self):
        with tempfile.NamedTemporaryFile() as db_file:
            CONF.set_override('database', db_file.name)
            node_cache.init()

            self.assertIsNotNone(node_cache._DB_NAME)
            # Verify that table exists
            node_cache._db().execute("select * from nodes")

    def test_create_dir(self):
        temp = tempfile.mkdtemp()
        CONF.set_override('database', os.path.join(temp, 'dir', 'file'))
        node_cache.init()

    def test_no_database(self):
        CONF.set_override('database', '')
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
        # invalidate cache
        old_options = self.node_info.options
        self.node_info.invalidate_cache()
        self.assertIsNot(old_options, self.node_info.options)
        self.assertEqual(old_options, self.node_info.options)

    def test_set(self):
        data = {'s': 'value', 'b': True, 'i': 42}
        self.node_info.set_option('name', data)
        self.assertEqual(data, self.node_info.options['name'])

        new = node_cache.NodeInfo(uuid=self.uuid, started_at=3.14)
        self.assertEqual(data, new.options['name'])


@mock.patch.object(utils, 'get_client')
class TestNodeCacheIronicObjects(unittest.TestCase):
    def setUp(self):
        super(TestNodeCacheIronicObjects, self).setUp()
        self.ports = {'mac1': mock.Mock(address='mac1', spec=['address']),
                      'mac2': mock.Mock(address='mac2', spec=['address'])}

    def test_node_provided(self, mock_ironic):
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        node=mock.sentinel.node)
        self.assertIs(mock.sentinel.node, node_info.node())
        self.assertIs(mock.sentinel.node, node_info.node(ironic='ironic'))
        self.assertFalse(mock_ironic.called)

    def test_node_not_provided(self, mock_ironic):
        mock_ironic.return_value.node.get.return_value = mock.sentinel.node
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0)

        self.assertIs(mock.sentinel.node, node_info.node())
        self.assertIs(node_info.node(), node_info.node())

        mock_ironic.assert_called_once_with()
        mock_ironic.return_value.node.get.assert_called_once_with('uuid')

    def test_node_ironic_arg(self, mock_ironic):
        ironic2 = mock.Mock()
        ironic2.node.get.return_value = mock.sentinel.node
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0)

        self.assertIs(mock.sentinel.node, node_info.node(ironic=ironic2))
        self.assertIs(node_info.node(), node_info.node(ironic=ironic2))

        self.assertFalse(mock_ironic.called)
        ironic2.node.get.assert_called_once_with('uuid')

    def test_ports_provided(self, mock_ironic):
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        ports=self.ports)
        self.assertIs(self.ports, node_info.ports())
        self.assertIs(self.ports, node_info.ports(ironic='ironic'))
        self.assertFalse(mock_ironic.called)

    def test_ports_provided_list(self, mock_ironic):
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        ports=list(self.ports.values()))
        self.assertEqual(self.ports, node_info.ports())
        self.assertEqual(self.ports, node_info.ports(ironic='ironic'))
        self.assertFalse(mock_ironic.called)

    def test_ports_not_provided(self, mock_ironic):
        mock_ironic.return_value.node.list_ports.return_value = list(
            self.ports.values())
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0)

        self.assertEqual(self.ports, node_info.ports())
        self.assertIs(node_info.ports(), node_info.ports())

        mock_ironic.assert_called_once_with()
        mock_ironic.return_value.node.list_ports.assert_called_once_with(
            'uuid', limit=0)

    def test_ports_ironic_arg(self, mock_ironic):
        ironic2 = mock.Mock()
        ironic2.node.list_ports.return_value = list(self.ports.values())
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0)

        self.assertEqual(self.ports, node_info.ports(ironic=ironic2))
        self.assertIs(node_info.ports(), node_info.ports(ironic=ironic2))

        self.assertFalse(mock_ironic.called)
        ironic2.node.list_ports.assert_called_once_with('uuid', limit=0)
