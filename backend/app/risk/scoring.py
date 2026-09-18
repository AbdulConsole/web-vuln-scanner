"""
Risk scoring primitives (Section 13/16).

RiskModel is the pluggable strategy interface: a named, documented
weighting scheme. Multiple models can coexist (see risk/models/) so
different prioritization approaches can be compared against the exact
same finding set later (Section 30's research-evaluation requirement)
without re-running detectors -- only the scoring step needs to re-run.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class FactorContribution:
    """One factor's contribution to a finding's final score.

    This is what gets persisted as a RiskScoreBreakdown row (Milestone 2)
    and is the raw material the Prioritization Engine (Milestone 10) uses
    to build its "why this finding is ranked here" explanation (Section 15)
    -- that engine reads these rows back rather than re-deriving an
    explanation from the final score alone.
    """

    factor_name: str
    raw_value: float  # the normalized [0.0, 1.0] input value
    weight: float  # this model's weight (or confidence multiplier) applied
    contribution: float  # this factor's point contribution to the 0-100 score


@dataclass(frozen=True)
class RiskScoreResult:
    score: float  # final, clamped 0-100 score
    breakdown: list[FactorContribution]


class RiskModel(ABC):
    """A named, versionable risk-scoring strategy.

    Subclasses only declare weights (and optionally override the
    confidence curve); the 0-100 normalization and clamping are handled
    uniformly by RiskCalculator (engine.py) so every model produces a
    score on the same scale and can be fairly compared.
    """

    name: str = ""
    description: str = ""

    @abstractmethod
    def weights(self) -> dict[str, float]:
        """Return {factor_name: weight} for severity/exploitability/impact/
        exposure. Weights are expected to sum to 1.0 so a finding with
        every factor at 1.0 and full confidence scores exactly 100 --
        RiskCalculator does not enforce this (an experimental model may
        deliberately explore non-normalized weights), but deviating from
        it means scores are no longer directly comparable to a model that
        does sum to 1.0.
        """
        raise NotImplementedError

    def confidence_multiplier(self, confidence: float) -> float:
        """How much to scale the weighted base score by, given detector
        confidence. Default: linear (a 0.5-confidence finding contributes
        half the risk of an identical 1.0-confidence one). Subclasses may
        override for a different curve -- see ConservativeRiskModel for a
        squared curve that punishes low confidence more harshly.
        """
        return confidence


# Score -> qualitative band (Section 13). Upper bounds are inclusive so
# every value in [0, 100] maps to exactly one band with no gaps.
RISK_BANDS: list[tuple[float, float, str]] = [
    (0.0, 19.999999, "informational"),
    (20.0, 39.999999, "low"),
    (40.0, 59.999999, "medium"),
    (60.0, 79.999999, "high"),
    (80.0, 100.0, "critical"),
]


def score_to_band(score: float) -> str:
    """Map a 0-100 risk score to its qualitative band. Values outside
    [0, 100] (which should not occur given RiskCalculator's clamping, but
    might from a hand-constructed score in a test) clamp to the nearest
    band rather than raising.
    """
    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label
    return "informational" if score < 0 else "critical"
