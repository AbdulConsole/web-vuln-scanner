"""
Risk Engine (Section 13): computes and persists a 0-100 risk score, with
an explainable per-factor breakdown, for findings using a pluggable
RiskModel.

Deliberately does NOT rank findings against each other or assign
priority_rank -- that cross-finding comparison and the "why this finding
outranks that one" explanation is the Prioritization Engine's job
(Milestone 10), which consumes the risk_score and RiskScoreBreakdown rows
this module writes. Keeping the two separate means a risk *model* can be
swapped (Section 16) without touching ranking logic, and a ranking
*strategy* can be swapped without touching scoring arithmetic.
"""
from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, RiskScoreBreakdown
from app.risk.factors import RiskFactorInput, exposure_to_score, severity_to_score
from app.risk.models.default import DefaultRiskModel
from app.risk.scoring import FactorContribution, RiskModel, RiskScoreResult


def _clamp(value: float) -> float:
    """Defensive [0.0, 1.0] clamp.

    Inputs should already be bounded -- severity/exposure mappings are
    fixed lookup tables, and exploitability/impact/confidence come from
    Finding columns with DB-level CHECK constraints (Milestone 2) -- but a
    RiskFactorInput can also be hand-constructed directly (tests do this),
    so this is a cheap extra safety net rather than trusting every caller.
    """
    return max(0.0, min(1.0, value))


class RiskCalculator:
    """Applies one RiskModel's weights to a finding's factor inputs,
    producing a 0-100 score plus a per-factor breakdown. Pure function of
    its inputs -- no database access, so it's trivially unit-testable."""

    def __init__(self, model: RiskModel):
        self.model = model

    def calculate(self, factor_input: RiskFactorInput) -> RiskScoreResult:
        weights = self.model.weights()
        factor_values = {
            "severity": _clamp(factor_input.severity),
            "exploitability": _clamp(factor_input.exploitability),
            "impact": _clamp(factor_input.impact),
            "exposure": _clamp(factor_input.exposure),
        }

        breakdown: list[FactorContribution] = []
        base_score = 0.0
        for factor_name, raw_value in factor_values.items():
            weight = weights.get(factor_name, 0.0)
            contribution = raw_value * weight * 100.0
            base_score += contribution
            breakdown.append(
                FactorContribution(
                    factor_name=factor_name,
                    raw_value=raw_value,
                    weight=weight,
                    contribution=contribution,
                )
            )

        confidence = _clamp(factor_input.confidence)
        multiplier = self.model.confidence_multiplier(confidence)
        final_score = max(0.0, min(100.0, base_score * multiplier))

        # The confidence adjustment is recorded as its own breakdown row
        # too, so Section 15's "why this finding is ranked here"
        # explanation can show the confidence effect explicitly, rather
        # than it being an invisible gap between the sum of the other
        # factors and the final score.
        breakdown.append(
            FactorContribution(
                factor_name="confidence_adjustment",
                raw_value=confidence,
                weight=multiplier,
                contribution=final_score - base_score,
            )
        )

        return RiskScoreResult(score=final_score, breakdown=breakdown)

    def calculate_for_finding(self, finding: Finding) -> RiskScoreResult:
        """Build a RiskFactorInput directly from a Finding ORM row's
        stored fields and score it."""
        factor_input = RiskFactorInput(
            severity=severity_to_score(finding.severity),
            exploitability=finding.exploitability,
            impact=finding.impact,
            exposure=exposure_to_score(finding.exposure),
            confidence=finding.confidence,
        )
        return self.calculate(factor_input)


class RiskEngine:
    """Scores a scan's findings and persists the results.

    For each Finding: computes its score via RiskCalculator, writes
    risk_score onto the Finding row, and persists one RiskScoreBreakdown
    row per contributing factor (including the confidence adjustment).
    Does not commit -- callers control the transaction boundary, matching
    the pattern established by the repository layer (Milestone 2/3) and
    EvidenceCollector (Milestone 8).
    """

    def __init__(self, session: AsyncSession, model: RiskModel | None = None):
        self.session = session
        self.model = model or DefaultRiskModel()
        self.calculator = RiskCalculator(self.model)

    async def score_finding(self, finding: Finding) -> RiskScoreResult:
        result = self.calculator.calculate_for_finding(finding)
        finding.risk_score = round(result.score, 2)

        for contribution in result.breakdown:
            self.session.add(
                RiskScoreBreakdown(
                    finding_id=finding.id,
                    factor_name=contribution.factor_name,
                    raw_value=contribution.raw_value,
                    weight=contribution.weight,
                    contribution=contribution.contribution,
                )
            )

        await self.session.flush()
        return result

    async def score_all(self, findings: Sequence[Finding]) -> list[RiskScoreResult]:
        return [await self.score_finding(finding) for finding in findings]
