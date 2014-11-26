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

import atexit
import logging
import os
import sqlite3
import tempfile
import time

from ironic_discoverd import conf
from ironic_discoverd import utils


LOG = logging.getLogger("discoverd")
_DB_NAME = None
_SCHEMA = """
create table if not exists nodes
 (uuid text primary key, started_at real);

create table if not exists attributes
 (name text, value text, uuid text,
  primary key (name, value),
  foreign key (uuid) references nodes);
"""


def init():
    """Initialize the database."""
    global _DB_NAME
    _DB_NAME = conf.get('discoverd', 'database').strip()
    if not _DB_NAME:
        # We can't use in-memory, so we create a temporary file
        fd, _DB_NAME = tempfile.mkstemp(prefix='discoverd-')
        os.close(fd)

        def cleanup():
            if os.path.exists(_DB_NAME):
                os.unlink(_DB_NAME)

        atexit.register(cleanup)
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
    drop_node(uuid)
    with _db() as db:
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
            except sqlite3.IntegrityError:
                raise utils.DiscoveryFailed(
                    'Some or all of %(name)s\'s %(value)s are already '
                    'on discovery' %
                    {'name': name, 'value': value})


def macs_on_discovery():
    """List all MAC's that are on discovery right now."""
    return {x[0] for x in _db().execute("select value from attributes "
                                        "where name='mac'")}


def drop_node(uuid):
    """Forget information about node with given uuid."""
    with _db() as db:
        db.execute("delete from nodes where uuid=?", (uuid,))
        db.execute("delete from attributes where uuid=?", (uuid,))


def pop_node(**attributes):
    """Find node in cache.

    This function also deletes a node from the cache, thus it's name.

    :param attributes: attributes known about this node (like macs, BMC etc)
    :returns: UUID or None
    """
    # NOTE(dtantsur): sorting is not required, but gives us predictability
    found = set()
    db = _db()
    for (name, value) in sorted(attributes.items()):
        if not value:
            LOG.warning('Empty value for attribute %s', name)
            continue
        if not isinstance(value, list):
            value = [value]

        LOG.debug('Trying to use %s %s for discovery' % (name, value))
        rows = db.execute('select distinct uuid from attributes where ' +
                          ' OR '.join('name=? AND value=?' for _ in value),
                          sum(([name, v] for v in value), [])).fetchall()
        if rows:
            found.update(item[0] for item in rows)

    if not found:
        LOG.error('Could not find a node based on attributes %s',
                  list(attributes))
        return
    elif len(found) > 1:
        LOG.error('Multiple nodes were matched based on attributes %(keys)s: '
                  '%(uuids)s',
                  {'keys': list(attributes),
                   'uuids': list(found)})
        return

    uuid = found.pop()
    drop_node(uuid)
    return uuid


def clean_up():
    """Reset discovery for timed out nodes.

    :return: list of timed out node UUID's
    """
    timeout = conf.getint('discoverd', 'timeout')
    if timeout <= 0:
        LOG.debug('Timeout is disabled')
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
