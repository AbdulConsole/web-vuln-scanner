"""
Attack surface models, populated by the crawler (Milestone 4).

These represent the structured discovery output described in Section 7 —
deliberately not raw HTML dumps. A Url can have many Forms and many
Parameters; detectors operate against these structured records rather than
re-parsing HTML themselves.
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    HTTP_METHOD_COLUMN_TYPE,
    PARAMETER_SOURCE_COLUMN_TYPE,
    HttpMethod,
    ParameterSource,
)

if TYPE_CHECKING:
    from app.models.scan import Scan


class Url(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "urls"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    method: Mapped[HttpMethod] = mapped_column(
        HTTP_METHOD_COLUMN_TYPE, default=HttpMethod.GET, nullable=False
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    response_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="urls")
    forms: Mapped[list[Form]] = relationship(
        back_populates="url", cascade="all, delete-orphan"
    )
    parameters: Mapped[list[Parameter]] = relationship(
        back_populates="url", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Url id={self.id} url={self.url!r} method={self.method}>"


class Form(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "forms"

    url_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("urls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[HttpMethod] = mapped_column(
        HTTP_METHOD_COLUMN_TYPE, default=HttpMethod.POST, nullable=False
    )
    # List of {"name": ..., "type": ..., "value": ...} dicts describing each
    # input field. Kept as JSON rather than a further-normalized table since
    # this is read as a unit by detectors and never queried by field name.
    inputs: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )

    url: Mapped[Url] = relationship(back_populates="forms")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Form id={self.id} action={self.action!r}>"


class Parameter(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "parameters"

    url_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("urls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[ParameterSource] = mapped_column(
        PARAMETER_SOURCE_COLUMN_TYPE, nullable=False
    )
    sample_value: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    url: Mapped[Url] = relationship(back_populates="parameters")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Parameter id={self.id} name={self.name!r} source={self.source}>"
