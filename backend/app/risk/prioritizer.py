"""
Prioritization Engine (Section 15): ranks scored findings by risk_score
and generates human-readable explanations for each ranking.

Consumes the risk_score and RiskScoreBreakdown rows written by RiskEngine
(Milestone 9). Does not re-score -- it only compares and ranks.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.enums import Severity
from app.models.finding import Finding, RiskScoreBreakdown
from app.risk.scoring import score_to_band

# Severity ordinal for tiebreaking (lower index = higher priority).
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


@dataclass(frozen=True)
class PrioritizedFinding:
    """A finding with its assigned rank and a human-readable explanation
    of why it ranked where it did."""

    finding: Finding
    rank: int
    explanation: str
    risk_band: str


def _build_explanation(
    finding: Finding,
    breakdowns: list[RiskScoreBreakdown],
    rank: int,
) -> str:
    """Generate a natural-language explanation for a finding's rank,
    referencing its top contributing risk factors.

    The explanation reads the RiskScoreBreakdown rows persisted by
    RiskEngine rather than re-deriving contributions from raw scores,
    so it always reflects the actual stored computation.
    """
    if not breakdowns:
        return f"Ranked #{rank} with risk score {finding.risk_score or 0:.1f}."

    # Sort by absolute contribution descending; skip the confidence_adjustment
    # row for the "top factors" list (it's mentioned separately if significant).
    factor_breakdowns = [b for b in breakdowns if b.factor_name != "confidence_adjustment"]
    sorted_factors = sorted(factor_breakdowns, key=lambda b: b.contribution, reverse=True)

    # Pick the top 2-3 contributors (those with contribution > 0).
    top = [f for f in sorted_factors if f.contribution > 0][:3]

    band = score_to_band(finding.risk_score or 0)
    parts = [f"Ranked #{rank} (risk score {finding.risk_score:.1f}, band: {band})"]

    if top:
        factor_descriptions = []
        for fb in top:
            factor_name = fb.factor_name.replace("_", " ")
            factor_descriptions.append(
                f"{factor_name} contributed {fb.contribution:.1f} pts "
                f"(raw={fb.raw_value:.2f}, weight={fb.weight:.2f})"
            )
        parts.append("Top factors: " + "; ".join(factor_descriptions))

    # Mention confidence adjustment if it had a significant effect.
    conf = next((b for b in breakdowns if b.factor_name == "confidence_adjustment"), None)
    if conf and abs(conf.contribution) > 1.0:
        direction = "increased" if conf.contribution > 0 else "decreased"
        parts.append(
            f"Confidence adjustment {direction} score by {abs(conf.contribution):.1f} pts "
            f"(confidence={conf.raw_value:.2f})"
        )

    return ". ".join(parts) + "."


class Prioritizer:
    """Ranks findings for a scan by risk_score and persists priority_rank.

    Does not commit -- callers control the transaction boundary, matching
    the pattern established by RiskEngine and EvidenceCollector.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def rank_all(self, scan_id) -> list[PrioritizedFinding]:
        """Fetch all scored findings for a scan, rank them, persist ranks,
        and return prioritized findings with explanations."""
        result = await self.session.execute(
            select(Finding)
            .options(selectinload(Finding.risk_breakdowns))
            .where(Finding.scan_id == scan_id)
            .where(Finding.risk_score.isnot(None))
        )
        findings = list(result.scalars().all())

        if not findings:
            return []

        # Sort: risk_score DESC, then confidence DESC, then severity ordinal ASC.
        findings.sort(
            key=lambda f: (
                -(f.risk_score or 0),
                -(f.confidence or 0),
                _SEVERITY_ORDER.get(f.severity, 99),
            )
        )

        prioritized: list[PrioritizedFinding] = []
        for idx, finding in enumerate(findings, start=1):
            rank = idx
            finding.priority_rank = rank
            explanation = _build_explanation(finding, finding.risk_breakdowns, rank)
            risk_band = score_to_band(finding.risk_score or 0)
            prioritized.append(
                PrioritizedFinding(
                    finding=finding,
                    rank=rank,
                    explanation=explanation,
                    risk_band=risk_band,
                )
            )

        await self.session.flush()
        return prioritized
