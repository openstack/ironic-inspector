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


from oslo_db.sqlalchemy import models
from oslo_db.sqlalchemy import types as db_types
from sqlalchemy import (Boolean, Column, DateTime, Enum, ForeignKey,
                        Integer, String, Text)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm

from ironic_inspector import introspection_state as istate


class ModelBase(models.ModelBase):
    __table_args__ = {'mysql_engine': "InnoDB",
                      'mysql_charset': "utf8"}


Base = declarative_base(cls=ModelBase)


class Node(Base):
    __tablename__ = 'nodes'
    uuid = Column(String(36), primary_key=True)
    # NOTE(TheJulia): Version ID use has been removed from inspector.
    # At some point, we can safely remove the column, but most likely
    # the project will encourage migration to a combined service as
    # opposed to a standalone service.
    version_id = Column(String(36), server_default='')
    state = Column(Enum(*istate.States.all()), nullable=False,
                   default=istate.States.finished,
                   server_default=istate.States.finished)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    manage_boot = Column(Boolean, nullable=True, default=True)


class Attribute(Base):
    __tablename__ = 'attributes'
    uuid = Column(String(36), primary_key=True)
    node_uuid = Column(String(36), ForeignKey('nodes.uuid',
                                              name='fk_node_attribute'))
    name = Column(String(255), nullable=False)
    value = Column(String(255), nullable=True)


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
    scope = Column(String(255), nullable=True)

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
    invert = Column(Boolean, default=False)
    # NOTE(dtantsur): while all operations now require a field, I can also
    # imagine user-defined operations that do not, thus it's nullable.
    field = Column(Text)
    params = Column(db_types.JsonEncodedDict)

    def as_dict(self):
        res = self.params.copy()
        res['op'] = self.op
        res['field'] = self.field
        res['multiple'] = self.multiple
        res['invert'] = self.invert
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


class IntrospectionData(Base):
    __tablename__ = 'introspection_data'
    uuid = Column(String(36), ForeignKey('nodes.uuid'), primary_key=True)
    processed = Column(Boolean, default=False, primary_key=True)
    data = Column(db_types.JsonEncodedDict(mysql_as_long=True),
                  nullable=True)
