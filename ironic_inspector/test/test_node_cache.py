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

import json
import time
import unittest

import mock
from oslo_config import cfg

from ironic_inspector import db
from ironic_inspector import node_cache
from ironic_inspector.test import base as test_base
from ironic_inspector import utils

CONF = cfg.CONF


class TestNodeCache(test_base.NodeTest):
    def test_add_node(self):
        # Ensure previous node information is cleared
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.node.uuid).save(session)
            db.Node(uuid='uuid2').save(session)
            db.Attribute(name='mac',
                         value='11:22:11:22:11:22',
                         uuid=self.uuid).save(session)

        res = node_cache.add_node(self.node.uuid, mac=self.macs,
                                  bmc_address='1.2.3.4', foo=None)
        self.assertEqual(self.uuid, res.uuid)
        self.assertTrue(time.time() - 60 < res.started_at < time.time() + 60)

        res = (db.model_query(db.Node.uuid,
               db.Node.started_at).order_by(db.Node.uuid).all())
        self.assertEqual(['1a1a1a1a-2b2b-3c3c-4d4d-5e5e5e5e5e5e',
                          'uuid2'], [t.uuid for t in res])
        self.assertTrue(time.time() - 60 < res[0].started_at <
                        time.time() + 60)

        res = (db.model_query(db.Attribute.name,
                              db.Attribute.value, db.Attribute.uuid).
               order_by(db.Attribute.name, db.Attribute.value).all())
        self.assertEqual([('bmc_address', '1.2.3.4', self.uuid),
                          ('mac', self.macs[0], self.uuid),
                          ('mac', self.macs[1], self.uuid)],
                         [(row.name, row.value, row.uuid) for row in res])

    def test__delete_node(self):
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.node.uuid).save(session)
            db.Attribute(name='mac', value='11:22:11:22:11:22',
                         uuid=self.uuid).save(session)
            data = {'s': 'value', 'b': True, 'i': 42}
            encoded = json.dumps(data)
            db.Option(uuid=self.uuid, name='name', value=encoded).save(
                session)

        node_cache._delete_node(self.uuid)
        session = db.get_session()
        row_node = db.model_query(db.Node).filter_by(
            uuid=self.uuid).first()
        self.assertIsNone(row_node)
        row_attribute = db.model_query(db.Attribute).filter_by(
            uuid=self.uuid).first()
        self.assertIsNone(row_attribute)
        row_option = db.model_query(db.Option).filter_by(
            uuid=self.uuid).first()
        self.assertIsNone(row_option)

    @mock.patch.object(node_cache, '_list_node_uuids')
    @mock.patch.object(node_cache, '_delete_node')
    def test_delete_nodes_not_in_list(self, mock__delete_node,
                                      mock__list_node_uuids):
        uuid2 = 'uuid2'
        uuids = {self.uuid}
        mock__list_node_uuids.return_value = {self.uuid, uuid2}
        session = db.get_session()
        with session.begin():
            node_cache.delete_nodes_not_in_list(uuids)
        mock__delete_node.assert_called_once_with(uuid2)

    def test_add_node_duplicate_mac(self):
        session = db.get_session()
        with session.begin():
            db.Node(uuid='another-uuid').save(session)
            db.Attribute(name='mac', value='11:22:11:22:11:22',
                         uuid='another-uuid').save(session)
        self.assertRaises(utils.Error,
                          node_cache.add_node,
                          self.node.uuid, mac=['11:22:11:22:11:22'])

    def test_active_macs(self):
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.node.uuid).save(session)
            values = [('mac', '11:22:11:22:11:22', self.uuid),
                      ('mac', '22:11:22:11:22:11', self.uuid)]
            for value in values:
                db.Attribute(name=value[0], value=value[1],
                             uuid=value[2]).save(session)
        self.assertEqual({'11:22:11:22:11:22', '22:11:22:11:22:11'},
                         node_cache.active_macs())

    def test__list_node_uuids(self):
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.node.uuid).save(session)
            db.Node(uuid='uuid2').save(session)

        node_uuid_list = node_cache._list_node_uuids()
        self.assertEqual({self.uuid, 'uuid2'}, node_uuid_list)

    def test_add_attribute(self):
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.node.uuid).save(session)
        node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=42)
        node_info.add_attribute('key', 'value')
        res = db.model_query(db.Attribute.name,
                             db.Attribute.value,
                             db.Attribute.uuid,
                             session=session)
        res = res.order_by(db.Attribute.name, db.Attribute.value).all()
        self.assertEqual([('key', 'value', self.uuid)],
                         [tuple(row) for row in res])
        self.assertRaises(utils.Error, node_info.add_attribute,
                          'key', 'value')
        # check that .attributes got invalidated and reloaded
        self.assertEqual({'key': ['value']}, node_info.attributes)

    def test_attributes(self):
        node_info = node_cache.add_node(self.uuid,
                                        bmc_address='1.2.3.4',
                                        mac=self.macs)
        self.assertEqual({'bmc_address': ['1.2.3.4'],
                          'mac': self.macs},
                         node_info.attributes)
        # check invalidation
        session = db.get_session()
        with session.begin():
            db.Attribute(name='foo', value='bar', uuid=self.uuid).save(session)
        # still cached
        self.assertEqual({'bmc_address': ['1.2.3.4'],
                          'mac': self.macs},
                         node_info.attributes)
        node_info.invalidate_cache()
        self.assertEqual({'bmc_address': ['1.2.3.4'],
                          'mac': self.macs, 'foo': ['bar']},
                         node_info.attributes)


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
        session = db.get_session()
        with session.begin():
            (db.model_query(db.Node).filter_by(uuid=self.uuid).
                delete())
        self.assertRaises(utils.Error, node_cache.find_node,
                          bmc_address='1.2.3.4')

    def test_already_finished(self):
        session = db.get_session()
        with session.begin():
            (db.model_query(db.Node).filter_by(uuid=self.uuid).
                update({'finished_at': 42.0}))
        self.assertRaises(utils.Error, node_cache.find_node,
                          bmc_address='1.2.3.4')


class TestNodeCacheCleanUp(test_base.NodeTest):
    def setUp(self):
        super(TestNodeCacheCleanUp, self).setUp()
        self.started_at = 100.0
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.uuid, started_at=self.started_at).save(
                session)
            for v in self.macs:
                db.Attribute(name='mac', value=v, uuid=self.uuid).save(
                    session)
            db.Option(uuid=self.uuid, name='foo', value='bar').save(
                session)

    def test_no_timeout(self):
        CONF.set_override('timeout', 0)

        self.assertFalse(node_cache.clean_up())

        res = [tuple(row) for row in
               db.model_query(db.Node.finished_at,
                              db.Node.error).all()]
        self.assertEqual([(None, None)], res)
        self.assertEqual(len(self.macs),
                         db.model_query(db.Attribute).count())
        self.assertEqual(1, db.model_query(db.Option).count())

    @mock.patch.object(time, 'time')
    def test_ok(self, time_mock):
        time_mock.return_value = 1000

        self.assertFalse(node_cache.clean_up())

        res = [tuple(row) for row in db.model_query(
            db.Node.finished_at, db.Node.error).all()]
        self.assertEqual([(None, None)], res)
        self.assertEqual(len(self.macs),
                         db.model_query(db.Attribute).count())
        self.assertEqual(1, db.model_query(db.Option).count())

    @mock.patch.object(time, 'time')
    def test_timeout(self, time_mock):
        # Add a finished node to confirm we don't try to timeout it
        time_mock.return_value = self.started_at
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.uuid + '1', started_at=self.started_at,
                    finished_at=self.started_at + 60).save(session)
        CONF.set_override('timeout', 99)
        time_mock.return_value = (self.started_at + 100)

        self.assertEqual([self.uuid], node_cache.clean_up())

        res = [(row.finished_at, row.error) for row in
               db.model_query(db.Node).all()]
        self.assertEqual([(self.started_at + 100, 'Introspection timeout'),
                          (self.started_at + 60, None)],
                         res)
        self.assertEqual([], db.model_query(db.Attribute).all())
        self.assertEqual([], db.model_query(db.Option).all())

    def test_old_status(self):
        CONF.set_override('node_status_keep_time', 42)
        session = db.get_session()
        with session.begin():
            db.model_query(db.Node).update(
                {'finished_at': time.time() - 100})

        self.assertEqual([], node_cache.clean_up())

        self.assertEqual([], db.model_query(db.Node).all())


class TestNodeCacheGetNode(test_base.NodeTest):
    def test_ok(self):
        started_at = time.time() - 42
        session = db.get_session()
        with session.begin():
            db.Node(uuid=self.uuid, started_at=started_at).save(session)
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
        session = db.get_session()
        with session.begin():
            db.Option(uuid=self.uuid, name='foo', value='bar').save(
                session)

    def test_success(self):
        self.node_info.finished()

        session = db.get_session()
        with session.begin():
            self.assertEqual((42.0, None),
                             tuple(db.model_query(
                                   db.Node.finished_at,
                                   db.Node.error).first()))
            self.assertEqual([], db.model_query(db.Attribute,
                             session=session).all())
            self.assertEqual([], db.model_query(db.Option,
                             session=session).all())

    def test_error(self):
        self.node_info.finished(error='boom')

        self.assertEqual((42.0, 'boom'),
                         tuple(db.model_query(db.Node.finished_at,
                               db.Node.error).first()))
        self.assertEqual([], db.model_query(db.Attribute).all())
        self.assertEqual([], db.model_query(db.Option).all())


class TestInit(unittest.TestCase):
    def setUp(self):
        super(TestInit, self).setUp()

    def test_ok(self):
        db.init()
        session = db.get_session()
        db.model_query(db.Node, session=session)


class TestNodeInfoOptions(test_base.NodeTest):
    def setUp(self):
        super(TestNodeInfoOptions, self).setUp()
        node_cache.add_node(self.uuid,
                            bmc_address='1.2.3.4',
                            mac=self.macs)
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=3.14)
        session = db.get_session()
        with session.begin():
            db.Option(uuid=self.uuid, name='foo', value='"bar"').save(
                session)

    def test_get(self):
        self.assertEqual({'foo': 'bar'}, self.node_info.options)
        # should be cached
        self.assertEqual(self.node_info.options, self.node_info.options)
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


@mock.patch.object(utils, 'get_client', autospec=True)
class TestNodeCacheIronicObjects(unittest.TestCase):
    def setUp(self):
        super(TestNodeCacheIronicObjects, self).setUp()
        self.ports = {'mac1': mock.Mock(address='mac1', spec=['address']),
                      'mac2': mock.Mock(address='mac2', spec=['address'])}

    def test_node_provided(self, mock_ironic):
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        node=mock.sentinel.node)
        self.assertIs(mock.sentinel.node, node_info.node())
        self.assertFalse(mock_ironic.called)

    def test_node_not_provided(self, mock_ironic):
        mock_ironic.return_value.node.get.return_value = mock.sentinel.node
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0)

        self.assertIs(mock.sentinel.node, node_info.node())
        self.assertIs(node_info.node(), node_info.node())

        mock_ironic.assert_called_once_with()
        mock_ironic.return_value.node.get.assert_called_once_with('uuid')

    def test_node_ironic_preset(self, mock_ironic):
        mock_ironic2 = mock.Mock()
        mock_ironic2.node.get.return_value = mock.sentinel.node
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        ironic=mock_ironic2)
        self.assertIs(mock.sentinel.node, node_info.node())

        self.assertFalse(mock_ironic.called)
        mock_ironic2.node.get.assert_called_once_with('uuid')

    def test_ports_provided(self, mock_ironic):
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        ports=self.ports)
        self.assertIs(self.ports, node_info.ports())
        self.assertFalse(mock_ironic.called)

    def test_ports_provided_list(self, mock_ironic):
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        ports=list(self.ports.values()))
        self.assertEqual(self.ports, node_info.ports())
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

    def test_ports_ironic_preset(self, mock_ironic):
        mock_ironic2 = mock.Mock()
        mock_ironic2.node.list_ports.return_value = list(
            self.ports.values())
        node_info = node_cache.NodeInfo(uuid='uuid', started_at=0,
                                        ironic=mock_ironic2)
        self.assertEqual(self.ports, node_info.ports())

        self.assertFalse(mock_ironic.called)
        mock_ironic2.node.list_ports.assert_called_once_with(
            'uuid', limit=0)


class TestUpdate(test_base.NodeTest):
    def setUp(self):
        super(TestUpdate, self).setUp()
        self.ironic = mock.Mock()
        self.ports = {'mac%d' % i: mock.Mock(address='mac%d' % i, uuid=str(i))
                      for i in range(2)}
        self.node_info = node_cache.NodeInfo(uuid=self.uuid,
                                             started_at=0,
                                             node=self.node,
                                             ports=self.ports,
                                             ironic=self.ironic)

    def test_patch(self):
        self.ironic.node.update.return_value = mock.sentinel.node

        self.node_info.patch(['patch'])

        self.ironic.node.update.assert_called_once_with(self.uuid, ['patch'])
        self.assertIs(mock.sentinel.node, self.node_info.node())

    def test_update_properties(self):
        self.ironic.node.update.return_value = mock.sentinel.node

        self.node_info.update_properties(prop=42)

        patch = [{'op': 'add', 'path': '/properties/prop', 'value': 42}]
        self.ironic.node.update.assert_called_once_with(self.uuid, patch)
        self.assertIs(mock.sentinel.node, self.node_info.node())

    def test_update_capabilities(self):
        self.ironic.node.update.return_value = mock.sentinel.node
        self.node.properties['capabilities'] = 'foo:bar,x:y'

        self.node_info.update_capabilities(x=1, y=2)

        self.ironic.node.update.assert_called_once_with(self.uuid, mock.ANY)
        patch = self.ironic.node.update.call_args[0][1]
        new_caps = utils.capabilities_to_dict(patch[0]['value'])
        self.assertEqual({'foo': 'bar', 'x': '1', 'y': '2'}, new_caps)

    def test_replace_field(self):
        self.ironic.node.update.return_value = mock.sentinel.node
        self.node.extra['foo'] = 'bar'

        self.node_info.replace_field('/extra/foo', lambda v: v + '1')

        patch = [{'op': 'replace', 'path': '/extra/foo', 'value': 'bar1'}]
        self.ironic.node.update.assert_called_once_with(self.uuid, patch)
        self.assertIs(mock.sentinel.node, self.node_info.node())

    def test_replace_field_not_found(self):
        self.ironic.node.update.return_value = mock.sentinel.node

        self.assertRaises(KeyError, self.node_info.replace_field,
                          '/extra/foo', lambda v: v + '1')

    def test_replace_field_with_default(self):
        self.ironic.node.update.return_value = mock.sentinel.node

        self.node_info.replace_field('/extra/foo', lambda v: v + [42],
                                     default=[])

        patch = [{'op': 'add', 'path': '/extra/foo', 'value': [42]}]
        self.ironic.node.update.assert_called_once_with(self.uuid, patch)
        self.assertIs(mock.sentinel.node, self.node_info.node())

    def test_replace_field_same_value(self):
        self.ironic.node.update.return_value = mock.sentinel.node
        self.node.extra['foo'] = 'bar'

        self.node_info.replace_field('/extra/foo', lambda v: v)
        self.assertFalse(self.ironic.node.update.called)

    def test_patch_port(self):
        self.ironic.port.update.return_value = mock.sentinel.port

        self.node_info.patch_port(self.ports['mac0'], ['patch'])

        self.ironic.port.update.assert_called_once_with('0', ['patch'])
        self.assertIs(mock.sentinel.port,
                      self.node_info.ports()['mac0'])

    def test_patch_port_by_mac(self):
        self.ironic.port.update.return_value = mock.sentinel.port

        self.node_info.patch_port('mac0', ['patch'])

        self.ironic.port.update.assert_called_once_with('0', ['patch'])
        self.assertIs(mock.sentinel.port,
                      self.node_info.ports()['mac0'])

    def test_delete_port(self):
        self.node_info.delete_port(self.ports['mac0'])

        self.ironic.port.delete.assert_called_once_with('0')
        self.assertEqual(['mac1'], list(self.node_info.ports()))

    def test_delete_port_by_mac(self):
        self.node_info.delete_port('mac0')

        self.ironic.port.delete.assert_called_once_with('0')
        self.assertEqual(['mac1'], list(self.node_info.ports()))


class TestNodeCacheGetByPath(test_base.NodeTest):
    def setUp(self):
        super(TestNodeCacheGetByPath, self).setUp()
        self.node = mock.Mock(spec=['uuid', 'properties'],
                              properties={'answer': 42},
                              uuid=self.uuid)
        self.node_info = node_cache.NodeInfo(uuid=self.uuid, started_at=0,
                                             node=self.node)

    def test_get_by_path(self):
        self.assertEqual(self.uuid, self.node_info.get_by_path('/uuid'))
        self.assertEqual(self.uuid, self.node_info.get_by_path('uuid'))
        self.assertEqual(42, self.node_info.get_by_path('/properties/answer'))
        self.assertRaises(KeyError, self.node_info.get_by_path, '/foo')
        self.assertRaises(KeyError, self.node_info.get_by_path, '/extra/foo')
