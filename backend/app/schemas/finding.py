"""
Finding-related Pydantic schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class EvidenceRead(BaseModel):
    id: uuid.UUID
    kind: str
    sanitized_payload: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, evidence: Any) -> EvidenceRead:
        return cls(
            id=evidence.id,
            kind=evidence.kind,
            sanitized_payload=evidence.sanitized_payload,
            created_at=evidence.created_at,
        )


class RiskBreakdownRead(BaseModel):
    id: uuid.UUID
    factor_name: str
    raw_value: float
    weight: float
    contribution: float

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, breakdown: Any) -> RiskBreakdownRead:
        return cls(
            id=breakdown.id,
            factor_name=breakdown.factor_name,
            raw_value=breakdown.raw_value,
            weight=breakdown.weight,
            contribution=breakdown.contribution,
        )


class FindingRead(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    url: str
    method: str
    parameter: str | None = None
    vulnerability_type: str
    title: str
    description: str
    severity: str
    confidence: float
    exploitability: float
    impact: float
    exposure: str
    risk_score: float | None = None
    priority_rank: int | None = None
    remediation: str | None = None
    references: list[str] = []
    detector_name: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, finding: Any) -> FindingRead:
        return cls(
            id=finding.id,
            scan_id=finding.scan_id,
            url=finding.url,
            method=finding.method.value if hasattr(finding.method, "value") else finding.method,
            parameter=finding.parameter,
            vulnerability_type=finding.vulnerability_type,
            title=finding.title,
            description=finding.description,
            severity=(
                finding.severity.value
                if hasattr(finding.severity, "value")
                else finding.severity
            ),
            confidence=finding.confidence,
            exploitability=finding.exploitability,
            impact=finding.impact,
            exposure=(
                finding.exposure.value
                if hasattr(finding.exposure, "value")
                else finding.exposure
            ),
            risk_score=finding.risk_score,
            priority_rank=finding.priority_rank,
            remediation=finding.remediation,
            references=finding.references or [],
            detector_name=finding.detector_name,
            status=finding.status.value if hasattr(finding.status, "value") else finding.status,
            created_at=finding.created_at,
            updated_at=finding.updated_at,
        )


class FindingDetail(FindingRead):
    """Finding with full evidence and risk breakdown."""
    evidence_items: list[EvidenceRead] = []
    risk_breakdowns: list[RiskBreakdownRead] = []

    @classmethod
    def from_model_with_details(cls, finding: Any) -> FindingDetail:
        base = cls.from_model(finding)
        return cls(
            **base.model_dump(),
            evidence_items=[
                EvidenceRead.from_model(e)
                for e in (finding.evidence_items or [])
            ],
            risk_breakdowns=[
                RiskBreakdownRead.from_model(b)
                for b in (finding.risk_breakdowns or [])
            ],
        )


class FindingList(BaseModel):
    items: list[FindingRead]
    total: int


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "confirmed", "false_positive", "resolved", "accepted_risk"]
