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

"""Cache for nodes currently under discovery."""

import logging
import sqlite3
import sys
import time

from ironic_discoverd import conf
from ironic_discoverd import utils


LOG = logging.getLogger("discoverd")
_DB_NAME = None
_SCHEMA = """
create table if not exists nodes
 (uuid text primary key, started_at real, finished_at real, error text);

create table if not exists attributes
 (name text, value text, uuid text,
  primary key (name, value),
  foreign key (uuid) references nodes);
"""


class NodeInfo(object):
    """Record about a node in the cache."""

    def __init__(self, uuid, started_at, finished_at=None, error=None):
        self.uuid = uuid
        self.started_at = started_at
        self.finished_at = finished_at
        self.error = error

    def finished(self, error=None, log=True):
        """Record status for this node.

        Also deletes look up attributes from the cache.

        :param error: error message
        :param log: whether to log the error message
        """
        self.finished_at = time.time()
        self.error = error
        if error and log:
            LOG.error(error)

        with _db() as db:
            db.execute('update nodes set finished_at=?, error=? where uuid=?',
                       (self.finished_at, error, self.uuid))
            db.execute("delete from attributes where uuid=?", (self.uuid,))


def init():
    """Initialize the database."""
    global _DB_NAME

    _DB_NAME = conf.get('discoverd', 'database').strip()
    if not _DB_NAME:
        LOG.critical('Configuration option discoverd.database should be set')
        sys.exit(1)

    sqlite3.connect(_DB_NAME).executescript(_SCHEMA)


def _db():
    if _DB_NAME is None:
        init()
    return sqlite3.connect(_DB_NAME)


def add_node(uuid, **attributes):
    """Store information about a node under discovery.

    All existing information about this node is dropped.
    Empty values are skipped.

    :param uuid: Ironic node UUID
    :param attributes: attributes known about this node (like macs, BMC etc)
    """
    with _db() as db:
        db.execute("delete from nodes where uuid=?", (uuid,))
        db.execute("delete from attributes where uuid=?", (uuid,))
        db.execute("insert into nodes(uuid, started_at) "
                   "values(?, ?)", (uuid, time.time()))
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
                LOG.error('Database integrity error %s, some or all of '
                          '%s\'s %s seem to be on discovery already',
                          exc, name, value)
                raise utils.DiscoveryFailed(
                    'Some or all of %(name)s\'s %(value)s are already '
                    'on discovery' %
                    {'name': name, 'value': value})


def macs_on_discovery():
    """List all MAC's that are on discovery right now."""
    return {x[0] for x in _db().execute("select value from attributes "
                                        "where name='mac'")}


def find_node(**attributes):
    """Find node in cache.

    :param attributes: attributes known about this node (like macs, BMC etc)
    :returns: structure NodeInfo with attributes ``uuid`` and ``created_at``
    :raises: DiscoveryFailed if node is not found
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
        LOG.error('Could not find a node based on attributes %s',
                  list(attributes))
        raise utils.DiscoveryFailed('Could not find a node', code=404)
    elif len(found) > 1:
        LOG.error('Multiple nodes were matched based on attributes %(keys)s: '
                  '%(uuids)s',
                  {'keys': list(attributes),
                   'uuids': list(found)})
        raise utils.DiscoveryFailed('Multiple matching nodes found', code=404)

    uuid = found.pop()
    row = (db.execute('select started_at from nodes where uuid=?', (uuid,))
           .fetchone())
    if not row:
        LOG.error('Inconsistent database: %s is in attributes table, '
                  'but not in nodes table', uuid)
        raise utils.DiscoveryFailed('Could not find a node', code=404)

    return NodeInfo(uuid=uuid, started_at=row[0])


def clean_up():
    """Reset discovery for timed out nodes.

    :return: list of timed out node UUID's
    """
    timeout = conf.getint('discoverd', 'timeout')
    if timeout <= 0:
        return []

    threshold = time.time() - timeout
    with _db() as db:
        uuids = [row[0] for row in db.execute('select uuid from nodes '
                                              'where started_at < ?',
                                              (threshold,))]
        if not uuids:
            return []

        LOG.error('Discovery for nodes %s has timed out', uuids)
        db.execute('delete from nodes where started_at < ?',
                   (threshold,))
        db.executemany('delete from attributes where uuid=?',
                       [(u,) for u in uuids])

    return uuids
