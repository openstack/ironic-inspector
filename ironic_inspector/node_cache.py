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

"""Cache for nodes currently under introspection."""

import copy
import json
import time

from ironicclient import exceptions
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log
from sqlalchemy import text

from ironic_inspector import db
from ironic_inspector.common.i18n import _, _LE, _LW
from ironic_inspector import utils

CONF = cfg.CONF


LOG = log.getLogger("ironic_inspector.node_cache")


MACS_ATTRIBUTE = 'mac'


class NodeInfo(object):
    """Record about a node in the cache."""

    def __init__(self, uuid, started_at, finished_at=None, error=None,
                 node=None, ports=None, ironic=None):
        self.uuid = uuid
        self.started_at = started_at
        self.finished_at = finished_at
        self.error = error
        self.invalidate_cache()
        self._node = node
        if ports is not None and not isinstance(ports, dict):
            ports = {p.address: p for p in ports}
        self._ports = ports
        self._attributes = None
        self._ironic = ironic

    @property
    def options(self):
        """Node introspection options as a dict."""
        if self._options is None:
            rows = db.model_query(db.Option).filter_by(
                uuid=self.uuid)
            self._options = {row.name: json.loads(row.value)
                             for row in rows}
        return self._options

    @property
    def attributes(self):
        """Node look up attributes as a dict."""
        if self._attributes is None:
            self._attributes = {}
            rows = db.model_query(db.Attribute).filter_by(
                uuid=self.uuid)
            for row in rows:
                self._attributes.setdefault(row.name, []).append(row.value)
        return self._attributes

    @property
    def ironic(self):
        """Ironic client instance."""
        if self._ironic is None:
            self._ironic = utils.get_client()
        return self._ironic

    def set_option(self, name, value):
        """Set an option for a node."""
        encoded = json.dumps(value)
        self.options[name] = value
        with db.ensure_transaction() as session:
            db.model_query(db.Option, session=session).filter_by(
                uuid=self.uuid, name=name).delete()
            db.Option(uuid=self.uuid, name=name, value=encoded).save(
                session)

    def finished(self, error=None):
        """Record status for this node.

        Also deletes look up attributes from the cache.

        :param error: error message
        """
        self.finished_at = time.time()
        self.error = error

        with db.ensure_transaction() as session:
            db.model_query(db.Node, session=session).filter_by(
                uuid=self.uuid).update(
                {'finished_at': self.finished_at, 'error': error})
            db.model_query(db.Attribute, session=session).filter_by(
                uuid=self.uuid).delete()
            db.model_query(db.Option, session=session).filter_by(
                uuid=self.uuid).delete()

    def add_attribute(self, name, value, session=None):
        """Store look up attribute for a node in the database.

        :param name: attribute name
        :param value: attribute value or list of possible values
        :param session: optional existing database session
        :raises: Error if attributes values are already in database
        """
        if not isinstance(value, list):
            value = [value]

        with db.ensure_transaction(session) as session:
            try:
                for v in value:
                    db.Attribute(name=name, value=v, uuid=self.uuid).save(
                        session)
            except db_exc.DBDuplicateEntry as exc:
                LOG.error(_LE('Database integrity error %s during '
                              'adding attributes'), exc)
                raise utils.Error(_(
                    'Some or all of %(name)s\'s %(value)s are already '
                    'on introspection') % {'name': name, 'value': value})
            # Invalidate attributes so they're loaded on next usage
            self._attributes = None

    @classmethod
    def from_row(cls, row, ironic=None):
        """Construct NodeInfo from a database row."""
        fields = {key: row[key]
                  for key in ('uuid', 'started_at', 'finished_at', 'error')}
        return cls(ironic=ironic, **fields)

    def invalidate_cache(self):
        """Clear all cached info, so that it's reloaded next time."""
        self._options = None
        self._node = None
        self._ports = None
        self._attributes = None
        self._ironic = None

    def node(self):
        """Get Ironic node object associated with the cached node record."""
        if self._node is None:
            self._node = self.ironic.node.get(self.uuid)
        return self._node

    def create_ports(self, macs):
        """Create one or several ports for this node.

        A warning is issued if port already exists on a node.
        """
        for mac in macs:
            if mac not in self.ports():
                self._create_port(mac)
            else:
                LOG.warn(_LW('Port %(mac)s already exists for node %(uuid)s, '
                             'skipping'), {'mac': mac, 'uuid': self.uuid})

    def ports(self):
        """Get Ironic port objects associated with the cached node record.

        This value is cached as well, use invalidate_cache() to clean.

        :return: dict MAC -> port object
        """
        if self._ports is None:
            self._ports = {p.address: p for p in
                           self.ironic.node.list_ports(self.uuid, limit=0)}
        return self._ports

    def _create_port(self, mac):
        try:
            port = self.ironic.port.create(node_uuid=self.uuid, address=mac)
        except exceptions.Conflict:
            LOG.warn(_LW('Port %(mac)s already exists for node %(uuid)s, '
                         'skipping'), {'mac': mac, 'uuid': self.uuid})
            # NOTE(dtantsur): we didn't get port object back, so we have to
            # reload ports on next access
            self._ports = None
        else:
            self._ports[mac] = port

    def patch(self, patches):
        """Apply JSON patches to a node.

        Refreshes cached node instance.

        :param patches: JSON patches to apply
        :raises: ironicclient exceptions
        """
        LOG.debug('Updating node %(uuid)s with patches %(patches)s',
                  {'uuid': self.uuid, 'patches': patches})
        self._node = self.ironic.node.update(self.uuid, patches)

    def patch_port(self, port, patches):
        """Apply JSON patches to a port.

        :param port: port object or its MAC
        :param patches: JSON patches to apply
        """
        ports = self.ports()
        if isinstance(port, str):
            port = ports[port]

        LOG.debug('Updating port %(mac)s of node %(uuid)s with patches '
                  '%(patches)s',
                  {'mac': port.address, 'uuid': self.uuid, 'patches': patches})
        new_port = self.ironic.port.update(port.uuid, patches)
        ports[port.address] = new_port

    def update_properties(self, **props):
        """Update properties on a node.

        :param props: properties to update
        """
        patches = [{'op': 'add', 'path': '/properties/%s' % k, 'value': v}
                   for k, v in props.items()]
        self.patch(patches)

    def update_capabilities(self, **caps):
        """Update capabilities on a node.

        :param props: capabilities to update
        """
        existing = utils.capabilities_to_dict(
            self.node().properties.get('capabilities'))
        existing.update(caps)
        self.update_properties(
            capabilities=utils.dict_to_capabilities(existing))

    def delete_port(self, port):
        """Delete port.

        :param port: port object or its MAC
        """
        ports = self.ports()
        if isinstance(port, str):
            port = ports[port]

        self.ironic.port.delete(port.uuid)
        del ports[port.address]

    def get_by_path(self, path):
        """Get field value by ironic-style path (e.g. /extra/foo).

        :param path: path to a field
        :returns: field value
        :raises: KeyError if field was not found
        """
        path = path.strip('/')
        try:
            if '/' in path:
                prop, key = path.split('/', 1)
                return getattr(self.node(), prop)[key]
            else:
                return getattr(self.node(), path)
        except AttributeError:
            raise KeyError(path)

    def replace_field(self, path, func, **kwargs):
        """Replace a field on ironic node.

        :param path: path to a field as used by the ironic client
        :param func: function accepting an old value and returning a new one
        :param kwargs: if 'default' value is passed here, it will be used when
                       no existing value is found.
        :raises: KeyError if value is not found and default is not set
        :raises: everything that patch() may raise
        """
        try:
            value = self.get_by_path(path)
            op = 'replace'
        except KeyError:
            if 'default' in kwargs:
                value = kwargs['default']
                op = 'add'
            else:
                raise

        ref_value = copy.deepcopy(value)
        value = func(value)
        if value != ref_value:
            self.patch([{'op': op, 'path': path, 'value': value}])


def add_node(uuid, **attributes):
    """Store information about a node under introspection.

    All existing information about this node is dropped.
    Empty values are skipped.

    :param uuid: Ironic node UUID
    :param attributes: attributes known about this node (like macs, BMC etc);
                       also ironic client instance may be passed under 'ironic'
    :returns: NodeInfo
    """
    started_at = time.time()
    with db.ensure_transaction() as session:
        _delete_node(uuid)
        db.Node(uuid=uuid, started_at=started_at).save(session)

        node_info = NodeInfo(uuid=uuid, started_at=started_at,
                             ironic=attributes.pop('ironic', None))
        for (name, value) in attributes.items():
            if not value:
                continue
            node_info.add_attribute(name, value, session=session)

    return node_info


def delete_nodes_not_in_list(uuids):
    """Delete nodes which don't exist in Ironic node UUIDs.

    :param uuids: Ironic node UUIDs
    """
    inspector_uuids = _list_node_uuids()
    for uuid in inspector_uuids - uuids:
        LOG.warn(_LW('Node %s was deleted from Ironic, dropping from Ironic '
                     'Inspector database'), uuid)
        _delete_node(uuid)


def _delete_node(uuid, session=None):
    """Delete information about a node.

    :param uuid: Ironic node UUID
    """
    with db.ensure_transaction(session) as session:
        (db.model_query(db.Node, session=session).filter_by(uuid=uuid).
            delete())
        (db.model_query(db.Attribute, session=session).filter_by(uuid=uuid).
            delete(synchronize_session=False))
        (db.model_query(db.Option, session=session).filter_by(uuid=uuid).
            delete())


def active_macs():
    """List all MAC's that are on introspection right now."""
    return ({x.value for x in db.model_query(db.Attribute.value).
            filter_by(name=MACS_ATTRIBUTE)})


def _list_node_uuids():
    """Get all nodes' uuid from cache.

    :returns: Set of nodes' uuid.
    """
    return {x.uuid for x in db.model_query(db.Node.uuid)}


def get_node(uuid, ironic=None):
    """Get node from cache by it's UUID.

    :param uuid: node UUID.
    :param ironic: optional ironic client instance
    :returns: structure NodeInfo.
    """
    row = db.model_query(db.Node).filter_by(uuid=uuid).first()
    if row is None:
        raise utils.Error(_('Could not find node %s in cache') % uuid,
                          code=404)
    return NodeInfo.from_row(row, ironic=ironic)


def find_node(**attributes):
    """Find node in cache.

    :param attributes: attributes known about this node (like macs, BMC etc)
                       also ironic client instance may be passed under 'ironic'
    :returns: structure NodeInfo with attributes ``uuid`` and ``created_at``
    :raises: Error if node is not found
    """
    ironic = attributes.pop('ironic', None)
    # NOTE(dtantsur): sorting is not required, but gives us predictability
    found = set()

    for (name, value) in sorted(attributes.items()):
        if not value:
            LOG.debug('Empty value for attribute %s', name)
            continue
        if not isinstance(value, list):
            value = [value]

        LOG.debug('Trying to use %s of value %s for node look up'
                  % (name, value))
        value_list = []
        for v in value:
            value_list.append('name="%s" AND value="%s"' % (name, v))
        stmt = ('select distinct uuid from attributes where ' +
                ' OR '.join(value_list))
        rows = (db.model_query(db.Attribute.uuid).from_statement(
            text(stmt)).all())
        if rows:
            found.update(item.uuid for item in rows)

    if not found:
        raise utils.NotFoundInCacheError(_(
            'Could not find a node for attributes %s') % attributes)
    elif len(found) > 1:
        raise utils.Error(_(
            'Multiple matching nodes found for attributes '
            '%(attr)s: %(found)s')
            % {'attr': attributes, 'found': list(found)}, code=404)

    uuid = found.pop()
    row = (db.model_query(db.Node.started_at, db.Node.finished_at).
           filter_by(uuid=uuid).first())

    if not row:
        raise utils.Error(_(
            'Could not find node %s in introspection cache, '
            'probably it\'s not on introspection now') % uuid, code=404)

    if row.finished_at:
        raise utils.Error(_(
            'Introspection for node %(node)s already finished on '
            '%(finish)s') % {'node': uuid, 'finish': row.finished_at})

    return NodeInfo(uuid=uuid, started_at=row.started_at, ironic=ironic)


def clean_up():
    """Clean up the cache.

    * Finish introspection for timed out nodes.
    * Drop outdated node status information.

    :return: list of timed out node UUID's
    """
    status_keep_threshold = (time.time() -
                             CONF.node_status_keep_time)

    with db.ensure_transaction() as session:
        db.model_query(db.Node, session=session).filter(
            db.Node.finished_at.isnot(None),
            db.Node.finished_at < status_keep_threshold).delete()

        timeout = CONF.timeout
        if timeout <= 0:
            return []
        threshold = time.time() - timeout
        uuids = [row.uuid for row in
                 db.model_query(db.Node.uuid, session=session).filter(
                     db.Node.started_at < threshold,
                     db.Node.finished_at.is_(None)).all()]
        if not uuids:
            return []

        LOG.error(_LE('Introspection for nodes %s has timed out'), uuids)
        query = db.model_query(db.Node, session=session).filter(
            db.Node.started_at < threshold,
            db.Node.finished_at.is_(None))
        query.update({'finished_at': time.time(),
                      'error': 'Introspection timeout'})
        for u in uuids:
            db.model_query(db.Attribute, session=session).filter_by(
                uuid=u).delete()
            db.model_query(db.Option, session=session).filter_by(
                uuid=u).delete()

    return uuids
