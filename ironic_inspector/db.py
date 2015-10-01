# Copyright 2015 NEC Corporation
# All Rights Reserved.
#
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

"""SQLAlchemy models for inspection data and shared database code."""

import contextlib

from oslo_config import cfg
from oslo_db import options as db_opts
from oslo_db.sqlalchemy import models
from oslo_db.sqlalchemy import session as db_session
from oslo_db.sqlalchemy import types as db_types
from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        String, Text)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm


Base = declarative_base(cls=models.ModelBase)
CONF = cfg.CONF

_FACADE = None


class Node(Base):
    __tablename__ = 'nodes'
    uuid = Column(String(36), primary_key=True)
    started_at = Column(Float, nullable=True)
    finished_at = Column(Float, nullable=True)
    error = Column(Text, nullable=True)


class Attribute(Base):
    __tablename__ = 'attributes'
    name = Column(String(255), primary_key=True)
    value = Column(String(255), primary_key=True)
    uuid = Column(String(36), ForeignKey('nodes.uuid'))


class Option(Base):
    __tablename__ = 'options'
    uuid = Column(String(36), ForeignKey('nodes.uuid'), primary_key=True)
    name = Column(String(255), primary_key=True)
    value = Column(Text)


class Rule(Base):
    __tablename__ = 'rules'
    uuid = Column(String(36), primary_key=True)
    created_at = Column(DateTime, nullable=False)
    description = Column(Text)
    # NOTE(dtantsur): in the future we might need to temporary disable a rule
    disabled = Column(Boolean, default=False)

    conditions = orm.relationship('RuleCondition', lazy='joined',
                                  order_by='RuleCondition.id',
                                  cascade="all, delete-orphan")
    actions = orm.relationship('RuleAction', lazy='joined',
                               order_by='RuleAction.id',
                               cascade="all, delete-orphan")


class RuleCondition(Base):
    __tablename__ = 'rule_conditions'
    id = Column(Integer, primary_key=True)
    rule = Column(String(36), ForeignKey('rules.uuid'))
    op = Column(String(255), nullable=False)
    multiple = Column(String(255), nullable=False)
    # NOTE(dtantsur): while all operations now require a field, I can also
    # imagine user-defined operations that do not, thus it's nullable.
    field = Column(Text)
    params = Column(db_types.JsonEncodedDict)

    def as_dict(self):
        res = self.params.copy()
        res['op'] = self.op
        res['field'] = self.field
        return res


class RuleAction(Base):
    __tablename__ = 'rule_actions'
    id = Column(Integer, primary_key=True)
    rule = Column(String(36), ForeignKey('rules.uuid'))
    action = Column(String(255), nullable=False)
    params = Column(db_types.JsonEncodedDict)

    def as_dict(self):
        res = self.params.copy()
        res['action'] = self.action
        return res


def init():
    """Initialize the database."""
    if CONF.discoverd.database:
        db_opts.set_defaults(CONF,
                             connection='sqlite:///%s' %
                             str(CONF.discoverd.database).strip())
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
def ensure_transaction(session=None):
    session = session or get_session()
    with session.begin(subtransactions=True):
        yield session
