"""
SQLAlchemy declarative base and shared mixins.

All models inherit from Base plus the mixins they need. Using mixins (rather
than repeating id/created_at/updated_at in every model) keeps the schema
consistent and avoids drift between tables.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Root declarative base. All ORM models must inherit from this so they
    share a single MetaData object, which Alembic autogeneration and
    ``Base.metadata.create_all`` both rely on."""


class UUIDPrimaryKeyMixin:
    """Adds a UUID primary key.

    ``Uuid(as_uuid=True)`` is used rather than a raw string column: it maps
    to a native UUID type on PostgreSQL and a CHAR(32) column on SQLite,
    so the same model works unmodified in development (SQLite) and
    production (PostgreSQL), per the project's portability requirement.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )


class TimestampMixin:
    """Adds created_at / updated_at columns maintained by the database."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
