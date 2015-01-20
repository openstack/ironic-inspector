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

import json
import logging
import os
import sqlite3
import sys
import time

from ironic_discoverd import conf
from ironic_discoverd import utils


LOG = logging.getLogger("ironic_discoverd.node_cache")
_DB_NAME = None
_SCHEMA = """
create table if not exists nodes
 (uuid text primary key, started_at real, finished_at real, error text);

create table if not exists attributes
 (name text, value text, uuid text,
  primary key (name, value),
  foreign key (uuid) references nodes);

create table if not exists options
 (uuid text, name text, value text,
  primary key (uuid, name),
  foreign key (uuid) references nodes);
"""


class NodeInfo(object):
    """Record about a node in the cache."""

    def __init__(self, uuid, started_at, finished_at=None, error=None):
        self.uuid = uuid
        self.started_at = started_at
        self.finished_at = finished_at
        self.error = error
        self._options = None

    @property
    def options(self):
        """Node introspection options as a dict."""
        if self._options is None:
            rows = _db().execute('select name, value from options '
                                 'where uuid=?', (self.uuid,))
            self._options = {row['name']: json.loads(row['value'])
                             for row in rows}
        return self._options

    def set_option(self, name, value):
        """Set an option for a node."""
        encoded = json.dumps(value)
        self.options[name] = value
        with _db() as db:
            db.execute('delete from options where uuid=? and name=?',
                       (self.uuid, name))
            db.execute('insert into options(uuid, name, value) values(?,?,?)',
                       (self.uuid, name, encoded))

    def finished(self, error=None):
        """Record status for this node.

        Also deletes look up attributes from the cache.

        :param error: error message
        """
        self.finished_at = time.time()
        self.error = error

        with _db() as db:
            db.execute('update nodes set finished_at=?, error=? where uuid=?',
                       (self.finished_at, error, self.uuid))
            db.execute("delete from attributes where uuid=?", (self.uuid,))
            db.execute("delete from options where uuid=?", (self.uuid,))

    @classmethod
    def from_row(cls, row):
        """Construct NodeInfo from a database row."""
        fields = {key: row[key]
                  for key in ('uuid', 'started_at', 'finished_at', 'error')}
        return cls(**fields)


def init():
    """Initialize the database."""
    global _DB_NAME

    _DB_NAME = conf.get('discoverd', 'database', default='').strip()
    if not _DB_NAME:
        LOG.critical('Configuration option discoverd.database should be set')
        sys.exit(1)

    db_dir = os.path.dirname(_DB_NAME)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir)
    sqlite3.connect(_DB_NAME).executescript(_SCHEMA)


def _db():
    if _DB_NAME is None:
        init()
    conn = sqlite3.connect(_DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def add_node(uuid, **attributes):
    """Store information about a node under introspection.

    All existing information about this node is dropped.
    Empty values are skipped.

    :param uuid: Ironic node UUID
    :param attributes: attributes known about this node (like macs, BMC etc)
    :returns: NodeInfo
    """
    started_at = time.time()
    with _db() as db:
        db.execute("delete from nodes where uuid=?", (uuid,))
        db.execute("delete from attributes where uuid=?", (uuid,))
        db.execute("delete from options where uuid=?", (uuid,))

        db.execute("insert into nodes(uuid, started_at) "
                   "values(?, ?)", (uuid, started_at))
        for (name, value) in attributes.items():
            if not value:
                continue
            if not isinstance(value, list):
                value = [value]

            try:
                db.executemany("insert into attributes(name, value, uuid) "
                               "values(?, ?, ?)",
                               [(name, v, uuid) for v in value])
            except sqlite3.IntegrityError as exc:
                LOG.error('Database integrity error %s during '
                          'adding attributes', exc)
                raise utils.Error(
                    'Some or all of %(name)s\'s %(value)s are already '
                    'on introspection' %
                    {'name': name, 'value': value})

    return NodeInfo(uuid=uuid, started_at=started_at)


def active_macs():
    """List all MAC's that are on introspection right now."""
    return {x[0] for x in _db().execute("select value from attributes "
                                        "where name='mac'")}


def get_node(uuid):
    """Get node from cache by it's UUID.

    :param uuid: node UUID.
    :returns: structure NodeInfo.
    """
    row = _db().execute('select * from nodes where uuid=?', (uuid,)).fetchone()
    if row is None:
        raise utils.Error('Could not find node %s in cache' % uuid, code=404)
    return NodeInfo.from_row(row)


def find_node(**attributes):
    """Find node in cache.

    :param attributes: attributes known about this node (like macs, BMC etc)
    :returns: structure NodeInfo with attributes ``uuid`` and ``created_at``
    :raises: Error if node is not found
    """
    # NOTE(dtantsur): sorting is not required, but gives us predictability
    found = set()
    db = _db()
    for (name, value) in sorted(attributes.items()):
        if not value:
            LOG.debug('Empty value for attribute %s', name)
            continue
        if not isinstance(value, list):
            value = [value]

        LOG.debug('Trying to use %s of value %s for node look up'
                  % (name, value))
        rows = db.execute('select distinct uuid from attributes where ' +
                          ' OR '.join('name=? AND value=?' for _ in value),
                          sum(([name, v] for v in value), [])).fetchall()
        if rows:
            found.update(item[0] for item in rows)

    if not found:
        raise utils.Error(
            'Could not find a node for attributes %s' % attributes, code=404)
    elif len(found) > 1:
        raise utils.Error(
            'Multiple matching nodes found for attributes %s: %s'
            % (attributes, list(found)), code=404)

    uuid = found.pop()
    row = db.execute('select started_at, finished_at from nodes where uuid=?',
                     (uuid,)).fetchone()
    if not row:
        raise utils.Error(
            'Could not find node %s in introspection cache, '
            'probably it\'s not on introspection now' % uuid, code=404)

    if row['finished_at']:
        raise utils.Error(
            'Introspection for node %s already finished on %s' %
            (uuid, row['finished_at']))

    return NodeInfo(uuid=uuid, started_at=row['started_at'])


def clean_up():
    """Clean up the cache.

    * Finish introspection for timed out nodes.
    * Drop outdated node status information.

    :return: list of timed out node UUID's
    """
    status_keep_threshold = (time.time() -
                             conf.getint('discoverd', 'node_status_keep_time'))

    with _db() as db:
        db.execute('delete from nodes where finished_at < ?',
                   (status_keep_threshold,))

    timeout = conf.getint('discoverd', 'timeout')
    if timeout <= 0:
        return []

    threshold = time.time() - timeout
    with _db() as db:
        uuids = [row[0] for row in
                 db.execute('select uuid from nodes where '
                            'started_at < ? and finished_at is null',
                            (threshold,))]
        if not uuids:
            return []

        LOG.error('Introspection for nodes %s has timed out', uuids)
        db.execute('update nodes set finished_at=?, error=? '
                   'where started_at < ? and finished_at is null',
                   (time.time(), 'Introspection timeout', threshold))
        db.executemany('delete from attributes where uuid=?',
                       [(u,) for u in uuids])
        db.executemany('delete from options where uuid=?',
                       [(u,) for u in uuids])

    return uuids
