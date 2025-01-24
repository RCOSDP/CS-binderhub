"""sqlalchemy ORM tools for the state of the constellation of processes"""
# Copy from https://github.com/jupyterhub/jupyterhub/blob/master/jupyterhub/orm.py
# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
import enum
import json
from base64 import decodebytes
from base64 import encodebytes
from datetime import datetime
from datetime import timedelta

import alembic.command
import alembic.config
from alembic.script import ScriptDirectory
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import event
from sqlalchemy import exc
from sqlalchemy import ForeignKey
from sqlalchemy import inspect
from sqlalchemy import Integer
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy import Table
from sqlalchemy import Unicode
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref
from sqlalchemy.orm import interfaces
from sqlalchemy.orm import object_session
from sqlalchemy.orm import relationship
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql.expression import bindparam
from sqlalchemy.types import LargeBinary
from sqlalchemy.types import Text
from sqlalchemy.types import TypeDecorator
from tornado.log import app_log

from jupyterhub.utils import compare_token
from jupyterhub.utils import hash_token
from jupyterhub.utils import new_token

from jupyterhub.orm import (
    utcnow, GrantType, DatabaseSchemaMismatch, register_foreign_keys,
    register_ping_connection, mysql_large_prefix_check, add_row_format,
)


Base = declarative_base()
Base.log = app_log


def get_user(user_name):
    return dict(kind='user', name=user_name)


class OAuthAccessToken(Base):
    __tablename__ = 'oauth_access_tokens'
    id = Column(Integer, primary_key=True, autoincrement=True)

    @staticmethod
    def now():
        return datetime.utcnow().timestamp()

    @property
    def api_id(self):
        return 'o%i' % self.id

    client_id = Column(Unicode(255), ForeignKey('oauth_clients.identifier', ondelete='CASCADE'))
    grant_type = Column(Enum(GrantType), nullable=False)
    token = Column(Unicode(255))
    expires_at = Column(Integer)
    refresh_token = Column(Unicode(255))
    refresh_expires_at = Column(Integer)
    user_name = Column(Unicode(1024))

    # the browser session id associated with a given token
    session_id = Column(Unicode(255))

    created = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, nullable=True)

    def __repr__(self):
        return "<{cls}('{prefix}...', client_id={client_id!r}, user_name={user_name!r}>".format(
            cls=self.__class__.__name__,
            client_id=self.client_id,
            user_name=self.user_name,
            prefix=self.prefix,
        )

    @classmethod
    def find(cls, db, token):
        orm_token = db.query(cls).filter(cls.token == token).first()
        if orm_token and not orm_token.client_id:
            app_log.warning(
                "Deleting stale oauth token for %s with no client",
                orm_token.user_name,
            )
            db.delete(orm_token)
            db.commit()
            return
        return orm_token

    @property
    def user(self):
        return get_user(self.user_name)


class OAuthCode(Base):
    __tablename__ = 'oauth_codes'
    id = Column(Integer, primary_key=True, autoincrement=True)
    client_id = Column(Unicode(255), ForeignKey('oauth_clients.identifier', ondelete='CASCADE'))
    code = Column(Unicode(36))
    expires_at = Column(Integer)
    redirect_uri = Column(Unicode(1023))
    session_id = Column(Unicode(255))
    user_name = Column(Unicode(1024))

    @staticmethod
    def now():
        return datetime.utcnow().timestamp()

    @classmethod
    def find(cls, db, code):
        return (
            db.query(cls)
            .filter(cls.code == code)
            .filter(or_(cls.expires_at == None, cls.expires_at >= cls.now()))
            .first()
        )

    @property
    def user(self):
        return get_user(self.user_name)


class OAuthClient(Base):
    __tablename__ = 'oauth_clients'
    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier = Column(Unicode(255), unique=True)
    description = Column(Unicode(1023))
    secret = Column(Unicode(255))
    redirect_uri = Column(Unicode(1023))

    @property
    def client_id(self):
        return self.identifier

    access_tokens = relationship(
        OAuthAccessToken,
        backref='client',
        cascade='all, delete-orphan',
    )
    codes = relationship(
        OAuthCode,
        backref='client',
        cascade='all, delete-orphan',
    )


def _expire_relationship(target, relationship_prop):
    """Expire relationship backrefs
    used when an object with relationships is deleted
    """

    session = object_session(target)
    # get peer objects to be expired
    peers = getattr(target, relationship_prop.key)
    if peers is None:
        # no peer to clear
        return
    # many-to-many and one-to-many have a list of peers
    # many-to-one has only one
    if (
        relationship_prop.direction is interfaces.MANYTOONE
        or not relationship_prop.uselist
    ):
        peers = [peers]
    for obj in peers:
        if inspect(obj).persistent:
            session.expire(obj, [relationship_prop.back_populates])


@event.listens_for(Session, "persistent_to_deleted")
def _notify_deleted_relationships(session, obj):
    """Expire relationships when an object becomes deleted
    Needed to keep relationships up to date.
    """
    mapper = inspect(obj).mapper
    for prop in mapper.relationships:
        if prop.back_populates:
            _expire_relationship(obj, prop)


def new_session_factory(
    url="sqlite:///:memory:", reset=False, expire_on_commit=False, **kwargs
):
    """Create a new session at url"""
    if url.startswith('sqlite'):
        kwargs.setdefault('connect_args', {'check_same_thread': False})

    elif url.startswith('mysql'):
        kwargs.setdefault('pool_recycle', 60)

    if url.endswith(':memory:'):
        # If we're using an in-memory database, ensure that only one connection
        # is ever created.
        kwargs.setdefault('poolclass', StaticPool)

    engine = create_engine(url, **kwargs)
    if url.startswith('sqlite'):
        register_foreign_keys(engine)

    # enable pessimistic disconnect handling
    register_ping_connection(engine)

    if reset:
        Base.metadata.drop_all(engine)

    if mysql_large_prefix_check(engine):  # if mysql is allows large indexes
        add_row_format(Base)  # set format on the tables

    Base.metadata.create_all(engine)

    # We set expire_on_commit=False, since we don't actually need
    # SQLAlchemy to expire objects after committing - we don't expect
    # concurrent runs of the hub talking to the same db. Turning
    # this off gives us a major performance boost
    session_factory = sessionmaker(bind=engine, expire_on_commit=expire_on_commit)
    return session_factory
