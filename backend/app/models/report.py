"""
Report model: metadata for a generated report artifact (Section 23).

The actual report content lives on disk (or object storage in production)
at storage_path; this row is just the index/metadata record so the API can
list and re-download previously generated reports.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, UUIDPrimaryKeyMixin
from app.models.enums import REPORT_FORMAT_COLUMN_TYPE, ReportFormat

if TYPE_CHECKING:
    from app.models.scan import Scan


class Report(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    format: Mapped[ReportFormat] = mapped_column(
        REPORT_FORMAT_COLUMN_TYPE, nullable=False
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    storage_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="reports")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Report id={self.id} scan_id={self.scan_id} format={self.format}>"
