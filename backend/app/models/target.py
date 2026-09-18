"""
Target model: the authorized scan boundary (Section 6 of the spec).

IMPORTANT: `auth_config` is currently stored as plain JSON. Encryption-at-
rest for stored credentials/tokens is a planned hardening item, not yet
implemented — see docs/architecture.md limitations. Do not store real
production credentials here until that lands.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan import Scan


class Target(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "targets"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # Additional domains explicitly authorized beyond the host of base_url
    # (e.g. a staging subdomain). Enforced by app.core.security.ScopeGuard.
    allowed_domains: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )

    # Crawl depth, rate limit, concurrency, detector selection, etc.
    scan_config: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )

    auth_config: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )

    scans: Mapped[list[Scan]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debug convenience
        return f"<Target id={self.id} name={self.name!r} base_url={self.base_url!r}>"
