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

import contextlib
import json
import logging
import time

from ironicclient import exceptions
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_db import options as db_opts
from oslo_db.sqlalchemy import session as db_session
from sqlalchemy import text

from ironic_inspector.common.i18n import _, _LE, _LW
from ironic_inspector import models
from ironic_inspector import utils

CONF = cfg.CONF


LOG = logging.getLogger("ironic_inspector.node_cache")
_FACADE = None


MACS_ATTRIBUTE = 'mac'


class NodeInfo(object):
    """Record about a node in the cache."""

    def __init__(self, uuid, started_at, finished_at=None, error=None,
                 node=None, ports=None):
        self.uuid = uuid
        self.started_at = started_at
        self.finished_at = finished_at
        self.error = error
        self.invalidate_cache()
        self._node = node
        if ports is not None and not isinstance(ports, dict):
            ports = {p.address: p for p in ports}
        self._ports = ports

    @property
    def options(self):
        """Node introspection options as a dict."""
        if self._options is None:
            rows = model_query(models.Option).filter_by(
                uuid=self.uuid)
            self._options = {row.name: json.loads(row.value)
                             for row in rows}
        return self._options

    def set_option(self, name, value):
        """Set an option for a node."""
        encoded = json.dumps(value)
        self.options[name] = value
        with _ensure_transaction() as session:
            model_query(models.Option, session=session).filter_by(
                uuid=self.uuid, name=name).delete()
            models.Option(uuid=self.uuid, name=name, value=encoded).save(
                session)

    def finished(self, error=None):
        """Record status for this node.

        Also deletes look up attributes from the cache.

        :param error: error message
        """
        self.finished_at = time.time()
        self.error = error

        with _ensure_transaction() as session:
            model_query(models.Node, session=session).filter_by(
                uuid=self.uuid).update(
                {'finished_at': self.finished_at, 'error': error})
            model_query(models.Attribute, session=session).filter_by(
                uuid=self.uuid).delete()
            model_query(models.Option, session=session).filter_by(
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

        with _ensure_transaction(session) as session:
            try:
                for v in value:
                    models.Attribute(name=name, value=v, uuid=self.uuid).save(
                        session)
            except db_exc.DBDuplicateEntry as exc:
                LOG.error(_LE('Database integrity error %s during '
                              'adding attributes'), exc)
                raise utils.Error(_(
                    'Some or all of %(name)s\'s %(value)s are already '
                    'on introspection') % {'name': name, 'value': value})

    @classmethod
    def from_row(cls, row):
        """Construct NodeInfo from a database row."""
        fields = {key: row[key]
                  for key in ('uuid', 'started_at', 'finished_at', 'error')}
        return cls(**fields)

    def invalidate_cache(self):
        """Clear all cached info, so that it's reloaded next time."""
        self._options = None
        self._node = None
        self._ports = None

    def node(self, ironic=None):
        """Get Ironic node object associated with the cached node record."""
        if self._node is None:
            ironic = utils.get_client() if ironic is None else ironic
            self._node = ironic.node.get(self.uuid)
        return self._node

    def create_ports(self, macs, ironic=None):
        """Create one or several ports for this node.

        A warning is issued if port already exists on a node.
        """
        ironic = utils.get_client() if ironic is None else ironic
        for mac in macs:
            if mac not in self.ports():
                self._create_port(mac, ironic)
            else:
                LOG.warn(_LW('Port %(mac)s already exists for node %(uuid)s, '
                             'skipping'), {'mac': mac, 'uuid': self.uuid})

    def ports(self, ironic=None):
        """Get Ironic port objects associated with the cached node record.

        This value is cached as well, use invalidate_cache() to clean.

        :return: dict MAC -> port object
        """
        if self._ports is None:
            ironic = utils.get_client() if ironic is None else ironic
            self._ports = {p.address: p
                           for p in ironic.node.list_ports(self.uuid, limit=0)}
        return self._ports

    def _create_port(self, mac, ironic):
        try:
            port = ironic.port.create(node_uuid=self.uuid, address=mac)
        except exceptions.Conflict:
            LOG.warn(_LW('Port %(mac)s already exists for node %(uuid)s, '
                         'skipping'), {'mac': mac, 'uuid': self.uuid})
            # NOTE(dtantsur): we didn't get port object back, so we have to
            # reload ports on next access
            self._ports = None
        else:
            self._ports[mac] = port


def init():
    """Initialize the database."""
    if CONF.discoverd.database:
        db_opts.set_defaults(CONF,
                             connection='sqlite:///%s' %
                             str(CONF.discoverd.database).strip())
    # TODO(yuikotakada) alembic migration
    engine = get_engine()
    models.Base.metadata.create_all(engine)
    return get_session()


def get_session(**kwargs):
    facade = _create_facade_lazily()
    return facade.get_session(**kwargs)


def get_engine():
    facade = _create_facade_lazily()
    return facade.get_engine()


def model_query(model, *args, **kwargs):
    """Query helper for simpler session usage.

    :param session: if present, the session to use
    """

    session = kwargs.get('session') or get_session()
    query = session.query(model, *args)
    return query


def _create_facade_lazily():
    global _FACADE
    if _FACADE is None:
        _FACADE = db_session.EngineFacade.from_config(cfg.CONF)
    return _FACADE


@contextlib.contextmanager
def _ensure_transaction(session=None):
    session = session or get_session()
    with session.begin(subtransactions=True):
        yield session


def add_node(uuid, **attributes):
    """Store information about a node under introspection.

    All existing information about this node is dropped.
    Empty values are skipped.

    :param uuid: Ironic node UUID
    :param attributes: attributes known about this node (like macs, BMC etc)
    :returns: NodeInfo
    """
    started_at = time.time()
    with _ensure_transaction() as session:
        (model_query(models.Node, session=session).filter_by(uuid=uuid).
            delete())
        (model_query(models.Attribute, session=session).filter_by(uuid=uuid).
            delete(synchronize_session=False))
        (model_query(models.Option, session=session).filter_by(uuid=uuid).
            delete())

        models.Node(uuid=uuid, started_at=started_at).save(session)

        node_info = NodeInfo(uuid=uuid, started_at=started_at)
        for (name, value) in attributes.items():
            if not value:
                continue
            node_info.add_attribute(name, value, session=session)

    return node_info


def active_macs():
    """List all MAC's that are on introspection right now."""
    return ({x.value for x in model_query(models.Attribute.value).
            filter_by(name=MACS_ATTRIBUTE)})


def get_node(uuid):
    """Get node from cache by it's UUID.

    :param uuid: node UUID.
    :returns: structure NodeInfo.
    """
    row = model_query(models.Node).filter_by(uuid=uuid).first()
    if row is None:
        raise utils.Error(_('Could not find node %s in cache') % uuid,
                          code=404)
    return NodeInfo.from_row(row)


def find_node(**attributes):
    """Find node in cache.

    :param attributes: attributes known about this node (like macs, BMC etc)
    :returns: structure NodeInfo with attributes ``uuid`` and ``created_at``
    :raises: Error if node is not found
    """
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
        rows = (model_query(models.Attribute.uuid).from_statement(
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
    row = (model_query(models.Node.started_at, models.Node.finished_at).
           filter_by(uuid=uuid).first())

    if not row:
        raise utils.Error(_(
            'Could not find node %s in introspection cache, '
            'probably it\'s not on introspection now') % uuid, code=404)

    if row.finished_at:
        raise utils.Error(_(
            'Introspection for node %(node)s already finished on '
            '%(finish)s') % {'node': uuid, 'finish': row.finished_at})

    return NodeInfo(uuid=uuid, started_at=row.started_at)


def clean_up():
    """Clean up the cache.

    * Finish introspection for timed out nodes.
    * Drop outdated node status information.

    :return: list of timed out node UUID's
    """
    status_keep_threshold = (time.time() -
                             CONF.node_status_keep_time)

    with _ensure_transaction() as session:
        model_query(models.Node, session=session).filter(
            models.Node.finished_at.isnot(None),
            models.Node.finished_at < status_keep_threshold).delete()

        timeout = CONF.timeout
        if timeout <= 0:
            return []
        threshold = time.time() - timeout
        uuids = [row.uuid for row in
                 model_query(models.Node.uuid, session=session).filter(
                     models.Node.started_at < threshold,
                     models.Node.finished_at.is_(None)).all()]
        if not uuids:
            return []

        LOG.error(_LE('Introspection for nodes %s has timed out'), uuids)
        query = model_query(models.Node, session=session).filter(
            models.Node.started_at < threshold,
            models.Node.finished_at.is_(None))
        query.update({'finished_at': time.time(),
                      'error': 'Introspection timeout'})
        for u in uuids:
            model_query(models.Attribute, session=session).filter_by(
                uuid=u).delete()
            model_query(models.Option, session=session).filter_by(
                uuid=u).delete()

    return uuids
