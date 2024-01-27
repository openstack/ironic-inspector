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

"""DB models API for inspection data and shared database code."""


import threading
import time

from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_db import options as db_opts
from oslo_db.sqlalchemy import enginefacade
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import delete
from sqlalchemy import insert
from sqlalchemy import or_, and_
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_errors
from sqlalchemy import update

from ironic_inspector.common.i18n import _
from ironic_inspector.db import model
from ironic_inspector import utils


LOG = utils.getProcessingLogger(__name__)

_DEFAULT_SQL_CONNECTION = 'sqlite:///ironic_inspector.sqlite'

_CONTEXT = threading.local()

db_opts.set_defaults(cfg.CONF, connection=_DEFAULT_SQL_CONNECTION)

CONF = cfg.CONF


def init():
    """Initialize the database.

    Method called on service start up, initialize transaction
    context manager and try to create db session.
    """
    get_writer_session()


def model_query(model, *args, **kwargs):
    """Query helper for simpler session usage.

    :param session: if present, the session to use
    """
    with session_for_read() as session:
        query = session.query(model, *args)
        return query


def get_writer_session():
    """Help method to get writer session.

    :returns: The writer session.
    """
    return enginefacade.writer.using(_CONTEXT)


def session_for_read():
    """Create read session within context manager"""
    return enginefacade.reader.using(_CONTEXT)


def session_for_write():
    """Create write session within context manager"""
    return enginefacade.writer.using(_CONTEXT)


def get_nodes():
    """Get list of cached nodes

    :returns: list of nodes, could be empty
    """
    with session_for_read() as session:
        res = session.query(
            model.Node
        ).order_by(
                model.Node.started_at.desc()
        )
        return [model.Node(uuid=entry.uuid, version_id=entry.version_id,
                state=entry.state, started_at=entry.started_at,
                finished_at=entry.finished_at, error=entry.error,
                manage_boot=entry.manage_boot)
                for entry in res.all()]


def get_node(uuid, **fields):
    """Get all cached nodes

    :param uuid: node uuid
    :param fields: fields are used as filtering criterion
    :returns: get node object
    :raises: NodeNotFoundInDBError in case node not found or node
             version differ from passed in fields.
    """
    try:
        with session_for_read() as session:
            res = session.query(model.Node).filter_by(
                uuid=uuid, **fields).one()
            return model.Node(uuid=res.uuid, version_id=res.version_id,
                              state=res.state, started_at=res.started_at,
                              finished_at=res.finished_at, error=res.error,
                              manage_boot=res.manage_boot)
    except (orm_errors.NoResultFound, orm_errors.StaleDataError):
        raise utils.NodeNotFoundInDBError()


def get_active_nodes(started_before=None):
    """Get list of nodes on introspection

    :param started_before: datetime object, returns nodes,
                           started before provided time
    :returns: list of nodes, could be empty
    """
    with session_for_read() as session:
        query = session.query(model.Node).filter_by(
            finished_at=None).order_by(model.Node.started_at.desc())

        if started_before:
            query = query.filter(model.Node.started_at < started_before)
        return [model.Node(uuid=entry.uuid, version_id=entry.version_id,
                           state=entry.state, started_at=entry.started_at,
                           finished_at=entry.finished_at, error=entry.error,
                           manage_boot=entry.manage_boot)
                for entry in query.all()]


def list_nodes_by_attributes(attributes):
    """Get list of nodes with certain attributes

    :param attributes: list of attributes as (name, value) pair
    :returns: list of nodes, could be empty
    """
    attr_filters = []
    for name, value in attributes:
        attr_filters.append(and_(model.Attribute.name == name,
                                 model.Attribute.value == value))
    with session_for_read() as session:
        query = session.query(
            model.Attribute
        ).filter(or_(*attr_filters)).all()
        result = [model.Attribute(uuid=attr.uuid, node_uuid=attr.node_uuid,
                                  name=attr.name, value=attr.value)
                  for attr in query]
    return result


@oslo_db_api.wrap_db_retry(max_retries=5, retry_on_deadlock=True)
def update_node(uuid, **values):
    """Update node by uuid

    Updates node fields with provided values, also bump node version.

    :param uuid: node uuid
    :param values: node fields with values to be updated
    :raises: NodeNotFoundInDBError in case node not found or node
             version differ from passed in values.
    """
    fields_ver = values.copy()
    with session_for_write() as session:
        stmt = update(
            model.Node
        ).where(
            model.Node.uuid == uuid
        ).values(
            fields_ver
        ).execution_options(
            synchronize_session=False
        )
        res = session.execute(stmt)
        if res.rowcount == 0:
            raise utils.NodeNotFoundInDBError()


def create_node(uuid, state, started_at=None, finished_at=None,
                error=None, manage_boot=None):
    """Create new node

    :param uuid: node uuid
    :param state: initial node state
    :param started_at: node caching datetime
    :param finished_at: introspection finished datetime
    :param error: introspection error
    :returns: created node object
    """
    node = model.Node(uuid=uuid, state=state, started_at=started_at,
                      finished_at=finished_at,
                      error=error, manage_boot=manage_boot)
    with session_for_write() as session:
        session.add(node)
    return node


def add_node(uuid, state, started_at=None, finished_at=None,
             error=None, manage_boot=None):
    """Add new node

    Before creating new node with certain uuid clean ups all existing
    node info.

    :param uuid: node uuid
    :param state: initial node state
    :param started_at: node caching datetime
    :param finished_at: introspection finished datetime
    :param error: introspection error
    :param manage_boot: whether to manage boot for this node
    :returns: created node object
    """
    with session_for_write() as session:
        # Delete attribute data
        session.execute(
            delete(model.Attribute).where(
                model.Attribute.node_uuid == uuid))
        # Delete introspection data
        session.execute(
            delete(model.Option).where(
                model.Option.uuid == uuid))
        session.execute(
            delete(model.IntrospectionData).where(
                model.IntrospectionData.uuid == uuid))
        # Delete the actual node
        session.execute(
            delete(model.Node).where(
                model.Node.uuid == uuid
            ).execution_options(synchronize_session=False)
        )
        node = model.Node(uuid=uuid, state=state, started_at=started_at,
                          finished_at=finished_at, error=error,
                          manage_boot=manage_boot)
        session.add(node)

    return node


def list_nodes_options_by_uuid(uuid):
    """Get list of node options

    :param uuid: node uuid
    :returns: list of node options, could be empty
    """
    with session_for_read() as session:
        query = session.query(model.Option).filter(model.Option.uuid == uuid)
        return [model.Option(uuid=opt.uuid, name=opt.name, value=opt.value)
                for opt in query.all()]


def delete_node(uuid):
    """Delete node and its attributes

    :param uuid: node uuid
    :returns: None
    """
    with session_for_write() as session:
        # Delete attribute data
        session.execute(
            delete(model.Attribute).where(
                model.Attribute.node_uuid == uuid))
        # Delete introspection data
        session.execute(
            delete(model.Option).where(
                model.Option.uuid == uuid))
        session.execute(
            delete(model.IntrospectionData).where(
                model.IntrospectionData.uuid == uuid))
        # Delete the actual node
        session.execute(
            delete(model.Node).where(
                model.Node.uuid == uuid
            ).execution_options(synchronize_session=False)
        )


def delete_nodes(finished_until=None):
    """Delete all nodes

    :param finished_until: datetime object, delete nodes are
                           introspected before finished_until time
    :returns: None
    """
    with session_for_read() as session:
        query = session.query(model.Node.uuid)
        if finished_until:
            query = query.filter(
                model.Node.finished_at.isnot(None),
                model.Node.finished_at < finished_until)
        uuid_list = []
        for node in query.all():
            # This breaks the requests up and allows proper value
            # deletion since there are structural dependencies on
            # for nodes in other tables. Performance wise this takes
            # a little slower overall, but doesn't cause the tables to
            # be locked, and handles the other tables without building
            # DB triggers.
            uuid_list.append(node[0])
    for uuid in uuid_list:
        delete_node(uuid)
        # Allow the Python GIL to let something else run, and
        # give the DB a chance to breath.
        time.sleep(0)


def set_option(node_uuid, name, value):
    """Set option for node

    :param node_uuid: node uuid
    :param name: option name
    :param value: option value
    :returns: None
    """
    with session_for_write() as session:
        opt = model.Option(uuid=node_uuid, name=name, value=value)
        session.add(opt)


def delete_options(**filters):
    """Delete all options

    :param filters: deletion filter criteria
    :returns: None
    """
    with session_for_write() as session:
        session.query(model.Option).filter_by(**filters).delete()


def set_attribute(node_uuid, name, values):
    """Set lookup attributes for node

    :param node_uuid: node uuid
    :param name: option name
    :param values: list of attribute values
    :returns: None
    """
    if not isinstance(values, list):
        values = [values]
    with session_for_write() as session:

        for value in values:
            attr = model.Attribute(node_uuid=node_uuid,
                                   uuid=uuidutils.generate_uuid(),
                                   name=name, value=value)
            session.add(attr)


def delete_attributes(uuid):
    """Delete all attributes

    :param uuid: the UUID of the node whose attributes you wish
                 tod elete
    :returns: None
    """
    # FIXME(TheJulia): This is going to be difficult to match
    # in later versions of sqlalchemy since query needs to move
    # to use the object model instead of free form attribute name.
    with session_for_write() as session:
        session.execute(
            delete(model.Attribute).where(
                model.Attribute.node_uuid == uuid))


def get_attributes(order_by=None, **fields):
    """Get all attributes

    :param order_by: ordering criterion
    :param fields: filter criteria fields
    :returns: list of attributes
    """
    # FIXME(TheJulia) This needs to be rewritten
    with session_for_read() as session:
        query = session.query(model.Attribute).filter_by(**fields)
        if order_by:
            orders = [getattr(model.Attribute, key) for key in order_by]
            query = query.order_by(*orders)
        res = query.all()

    result = [model.Attribute(uuid=attr.uuid, node_uuid=attr.node_uuid,
                              name=attr.name, value=attr.value)
              for attr in res]
    return result


def get_options(**fields):
    """Get all options

    :param fields: filter criteria fields
    :returns: list of options
    """
    return model_query(model.Option).filter_by(**fields).all()


def create_rule(uuid, conditions, actions, description=None,
                scope=None):
    """Create new rule

    :param uuid: rule uuid
    :param conditions: list of (field, op, multiple, invert, params) tuple,
                       which represents condition object
    :param actions: list of (action, params) pair, which represents action
                    object
    :param description: rule description
    :param scope: rule scope

    :returns: created rule
    """
    try:
        with session_for_write() as session:
            rule = model.Rule(
                uuid=uuid, description=description,
                disabled=False, created_at=timeutils.utcnow(), scope=scope)
            rule.conditions = rule.action = []
            for field, op, multiple, invert, params in conditions:
                rule.conditions.append(model.RuleCondition(op=op,
                                                           field=field,
                                                           multiple=multiple,
                                                           invert=invert,
                                                           params=params))

            for action, params in actions:
                rule.actions.append(model.RuleAction(action=action,
                                                     params=params))

            session.add(rule)
    except db_exc.DBDuplicateEntry as exc:
        LOG.error('Database integrity error %s when creating a rule', exc)
        raise utils.RuleUUIDExistError(uuid)
    return rule


def get_rule(uuid):
    """Get rule by uuid

    :param uuid: rule uuid
    :returns: rule object
    """
    try:
        with session_for_read() as session:
            query = session.query(model.Rule).where(
                model.Rule.uuid == uuid)
            rule = query.one()
            return model.Rule(uuid=rule.uuid, created_at=rule.created_at,
                              description=rule.description,
                              disabled=rule.disabled, scope=rule.scope,
                              conditions=rule.conditions, actions=rule.actions)
    except orm.exc.NoResultFound:
        raise utils.RuleNotFoundError(uuid)


def get_rules(**fields):
    """List all rules."""
    with session_for_read() as session:
        query = session.query(
            model.Rule
        ).filter_by(
            **fields
        ).order_by(
            model.Rule.created_at
        )
        return [model.Rule(
                    uuid=rule.uuid,
                    actions=rule.actions,
                    conditions=rule.conditions,
                    description=rule.description,
                    scope=rule.scope)
                for rule in query]


def get_rules_conditions(**fields):
    """Get all rule conditions

    :param fields: field filter criteria
    :returns: list of conditions
    """
    # NOTE(TheJulia): This appears to exist largely to help unit
    #                 testing of rules functionality.
    with session_for_read() as session:
        query = session.query(
            model.RuleCondition
        ).filter_by(**fields)
        return [model.RuleCondition(
                    id=condition.id,
                    rule=condition.rule,
                    op=condition.op,
                    multiple=condition.multiple,
                    invert=condition.invert,
                    field=condition.field,
                    params=condition.params)
                for condition in query.all()]


def get_rules_actions(**fields):
    """Get all rule actions

    :param fields: field filter criteria
    :returns: list of actions
    """
    # NOTE(TheJulia): This appears to exist largely to help unit
    #                 testing of rules functionality.
    with session_for_read() as session:
        query = session.query(
            model.RuleAction
        ).filter_by(**fields)
        return [model.RuleAction(
                    id=action.id,
                    rule=action.rule,
                    action=action.action,
                    params=action.params)
                for action in query.all()]


def delete_rule(uuid):
    """Delete the rule by uuid

    :param uuid: rule uuid
    :raises: RuleNotFoundError in case rule not found
    :returns: None
    """
    with session_for_write() as session:
        stmt = (
            delete(
                model.RuleAction
            ).where(
               model.RuleAction.rule == uuid
            ).execution_options(synchronize_session=False)
        )
        session.execute(stmt)

        stmt = (
            delete(
                model.RuleCondition
            ).where(
                model.RuleCondition.rule == uuid
            ).execution_options(synchronize_session=False)
        )
        session.execute(stmt)

        stmt = (
            delete(
                model.Rule
            ).where(
                model.Rule.uuid == uuid
            ).execution_options(synchronize_session=False)
        )
        res = session.execute(stmt)
        if res.rowcount == 0:
            raise utils.RuleNotFoundError(uuid)


def delete_all_rules():
    """Delete all rules

    :returns: None
    """
    with session_for_write() as session:
        session.execute(
            delete(model.RuleAction).execution_options(
                synchronize_session=False
            )
        )
        session.execute(
            delete(model.RuleCondition).execution_options(
                synchronize_session=False
            )
        )
        session.execute(
            delete(model.Rule).execution_options(
                synchronize_session=False
            )
        )
        session.commit()


def store_introspection_data(node_id, introspection_data,
                             processed=True):
    """Store introspection data for this node.

    :param node_id: node UUID.
    :param introspection_data: A dictionary of introspection data
    :param processed: Specify the type of introspected data, set to False
                      indicates the data is unprocessed.
    """
    updated = False
    with session_for_write() as session:
        record = session.query(model.IntrospectionData).filter_by(
            uuid=node_id, processed=processed).first()

        if record:
            record.update({'data': introspection_data})
            updated = True
        else:
            # by default, all write sessions are committed. In this
            # case, we can safely rollback. Once we rollback, we
            # launch a new session.
            session.rollback()
    if not updated:
        with session_for_write() as session:
            stmt = insert(model.IntrospectionData).values(
                {'uuid': node_id, 'processed': processed,
                 'data': introspection_data}
            )
            session.execute(stmt)


def get_introspection_data(node_id, processed=True):
    """Get introspection data for this node.

    :param node_id: node UUID.
    :param processed: Specify the type of introspected data, set to False
                      indicates retrieving the unprocessed data.
    :return: A dictionary representation of intropsected data
    """
    try:
        with session_for_read() as session:
            ref = session.query(model.IntrospectionData).filter_by(
                uuid=node_id, processed=processed).one()
        res = ref['data']
        return res
    except orm_errors.NoResultFound:
        msg = _('Introspection data not found for node %(node)s, '
                'processed=%(processed)s') % {'node': node_id,
                                              'processed': processed}
        raise utils.IntrospectionDataNotFound(msg)
