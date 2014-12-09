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

import time

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

        node_cache.add_node(self.node.uuid, mac=self.macs,
                            bmc_address='1.2.3.4', foo=None)

        res = self.db.execute("select uuid, started_at "
                              "from nodes order by uuid").fetchall()
        self.assertEqual(['uuid', 'uuid2'], [t[0] for t in res])
        self.assertTrue(time.time() - 60 < res[0][1] < time.time() + 60)

        res = self.db.execute("select name, value, uuid from attributes "
                              "order by name, value").fetchall()
        self.assertEqual([('bmc_address', '1.2.3.4', self.uuid),
                          ('mac', self.macs[0], self.uuid),
                          ('mac', self.macs[1], self.uuid)],
                         res)

    def test_add_node_duplicate_mac(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            ('another-uuid',))
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', 'another-uuid'))

        self.assertRaises(utils.DiscoveryFailed,
                          node_cache.add_node,
                          self.node.uuid, mac=['11:22:11:22:11:22'])

    def test_drop_node(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.execute("insert into nodes(uuid) values('uuid2')")
            self.db.execute("insert into attributes(name, value, uuid) "
                            "values(?, ?, ?)",
                            ('mac', '11:22:11:22:11:22', self.uuid))

        node_cache.drop_node(self.node.uuid)

        self.assertEqual([('uuid2',)], self.db.execute(
            "select uuid from nodes").fetchall())
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_macs_on_discovery(self):
        with self.db:
            self.db.execute("insert into nodes(uuid) values(?)",
                            (self.node.uuid,))
            self.db.executemany("insert into attributes(name, value, uuid) "
                                "values(?, ?, ?)",
                                [('mac', '11:22:11:22:11:22', self.uuid),
                                 ('mac', '22:11:22:11:22:11', self.uuid)])
        self.assertEqual({'11:22:11:22:11:22', '22:11:22:11:22:11'},
                         node_cache.macs_on_discovery())


class TestNodeCachePop(test_base.NodeTest):
    def setUp(self):
        super(TestNodeCachePop, self).setUp()
        self.macs2 = ['00:00:00:00:00:00']
        node_cache.add_node(self.uuid,
                            bmc_address='1.2.3.4',
                            mac=self.macs)

    def test_no_data(self):
        self.assertRaises(utils.DiscoveryFailed, node_cache.pop_node)
        self.assertRaises(utils.DiscoveryFailed, node_cache.pop_node, mac=[])

    def test_bmc(self):
        res = node_cache.pop_node(bmc_address='1.2.3.4')
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 1)
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_macs(self):
        res = node_cache.pop_node(mac=['11:22:33:33:33:33', self.macs[1]])
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 1)
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_macs_not_found(self):
        self.assertRaises(utils.DiscoveryFailed, node_cache.pop_node,
                          mac=['11:22:33:33:33:33',
                               '66:66:44:33:22:11'])

    def test_macs_multiple_found(self):
        node_cache.add_node('uuid2', mac=self.macs2)
        self.assertRaises(utils.DiscoveryFailed, node_cache.pop_node,
                          mac=[self.macs[0], self.macs2[0]])

    def test_both(self):
        res = node_cache.pop_node(bmc_address='1.2.3.4',
                                  mac=self.macs)
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 1)
        self.assertEqual([], self.db.execute(
            "select * from attributes").fetchall())

    def test_inconsistency(self):
        with self.db:
            self.db.execute('delete from nodes where uuid=?', (self.uuid,))
        self.assertRaises(utils.DiscoveryFailed, node_cache.pop_node,
                          bmc_address='1.2.3.4')


class TestNodeCacheCleanUp(test_base.NodeTest):
    def setUp(self):
        super(TestNodeCacheCleanUp, self).setUp()
        with self.db:
            self.db.execute('insert into nodes(uuid, started_at) '
                            'values(?, ?)', (self.uuid, time.time() - 3600000))
            self.db.executemany('insert into attributes(name, value, uuid) '
                                'values(?, ?, ?)',
                                [('mac', v, self.uuid) for v in self.macs])

    def test_no_timeout(self):
        conf.CONF.set('discoverd', 'timeout', '0')

        self.assertFalse(node_cache.clean_up())

        self.assertEqual(1, len(self.db.execute(
            'select * from nodes').fetchall()))
        self.assertEqual(len(self.macs), len(self.db.execute(
            'select * from attributes').fetchall()))

    @mock.patch.object(time, 'time')
    def test_ok(self, time_mock):
        time_mock.return_value = 1000

        self.assertFalse(node_cache.clean_up())

        self.assertEqual(1, len(self.db.execute(
            'select * from nodes').fetchall()))
        self.assertEqual(len(self.macs), len(self.db.execute(
            'select * from attributes').fetchall()))

    def test_cleaned(self):
        self.assertEqual([self.uuid], node_cache.clean_up())

        self.assertEqual([], self.db.execute('select * from nodes').fetchall())
        self.assertEqual([], self.db.execute(
            'select * from attributes').fetchall())
