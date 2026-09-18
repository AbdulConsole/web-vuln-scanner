"""
Scan model: one execution of the scan pipeline against a Target.

Lifecycle states (Section 18): queued -> running -> (paused) -> completed
                                                    -> failed
                                                    -> cancelled
State transitions are enforced by the scan service layer (Milestone 3), not
by this model — the model only stores the current state.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import SCAN_STATUS_COLUMN_TYPE, ScanStatus

if TYPE_CHECKING:
    from app.models.attack_surface import Url
    from app.models.finding import Finding
    from app.models.report import Report
    from app.models.target import Target


class Scan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        SCAN_STATUS_COLUMN_TYPE, default=ScanStatus.QUEUED, nullable=False, index=True
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    urls_crawled: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requests_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Frozen copy of the target's scan_config at scan-start time, so later
    # edits to the target's default config don't retroactively change how a
    # historical scan is interpreted/reported.
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )

    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    urls: Mapped[list[Url]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Scan id={self.id} target_id={self.target_id} status={self.status}>"
