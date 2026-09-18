"""
Finding model and its dependents (Section 11 finding schema, Section 12
evidence system, Section 13 risk score breakdown).

Findings deliberately store confidence/exploitability/impact/exposure as
separate columns rather than only a final risk_score: the risk engine
(Milestone 9) needs these individually to compute and *explain* the score,
and storing them lets us re-run different RiskModel strategies against the
same finding data later (Section 30's research-comparison requirement)
without re-running detectors.
"""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, CheckConstraint, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    EXPOSURE_LEVEL_COLUMN_TYPE,
    FINDING_STATUS_COLUMN_TYPE,
    HTTP_METHOD_COLUMN_TYPE,
    SEVERITY_COLUMN_TYPE,
    ExposureLevel,
    FindingStatus,
    HttpMethod,
    Severity,
)

if TYPE_CHECKING:
    from app.models.scan import Scan


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_finding_confidence_range",
        ),
        CheckConstraint(
            "exploitability >= 0.0 AND exploitability <= 1.0",
            name="ck_finding_exploitability_range",
        ),
        CheckConstraint(
            "impact >= 0.0 AND impact <= 1.0", name="ck_finding_impact_range"
        ),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0.0 AND risk_score <= 100.0)",
            name="ck_finding_risk_score_range",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[HttpMethod] = mapped_column(HTTP_METHOD_COLUMN_TYPE, nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)

    vulnerability_type: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False)

    severity: Mapped[Severity] = mapped_column(
        SEVERITY_COLUMN_TYPE, nullable=False, index=True
    )
    # Normalized 0.0-1.0 factor inputs to the risk engine. See
    # docs/risk-model.md (Milestone 9) for how these combine into risk_score.
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    exploitability: Mapped[float] = mapped_column(Float, nullable=False)
    impact: Mapped[float] = mapped_column(Float, nullable=False)
    exposure: Mapped[ExposureLevel] = mapped_column(
        EXPOSURE_LEVEL_COLUMN_TYPE, nullable=False
    )

    # Populated by the risk engine after detection; NULL until scored.
    risk_score: Mapped[float | None] = mapped_column(
        Float, nullable=True, index=True
    )
    priority_rank: Mapped[int | None] = mapped_column(
        Integer, nullable=True, index=True
    )

    remediation: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    detector_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        FINDING_STATUS_COLUMN_TYPE, default=FindingStatus.OPEN, nullable=False, index=True
    )

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence_items: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    risk_breakdowns: Mapped[list[RiskScoreBreakdown]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<Finding id={self.id} type={self.vulnerability_type} "
            f"severity={self.severity} risk_score={self.risk_score}>"
        )


class Evidence(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(100), nullable=False)

    # Sanitized by app.evidence.sanitizer (Milestone 8) BEFORE this row is
    # ever written. This column must never contain raw secrets, session
    # tokens, or credentials — sanitization happens at write time, not
    # read time, so no read path can accidentally expose raw data.
    sanitized_payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="evidence_items")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Evidence id={self.id} finding_id={self.finding_id} kind={self.kind!r}>"


class RiskScoreBreakdown(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One row per risk factor that contributed to a Finding's risk_score.

    This is what powers the "why this finding is ranked #1" explanation
    (Section 15) — the prioritization engine reads these rows back rather
    than re-deriving an explanation from the final score alone.
    """

    __tablename__ = "risk_score_breakdowns"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    factor_name: Mapped[str] = mapped_column(String(100), nullable=False)
    raw_value: Mapped[float] = mapped_column(Float, nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    contribution: Mapped[float] = mapped_column(Float, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="risk_breakdowns")

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<RiskScoreBreakdown finding_id={self.finding_id} "
            f"factor={self.factor_name!r} contribution={self.contribution}>"
        )
