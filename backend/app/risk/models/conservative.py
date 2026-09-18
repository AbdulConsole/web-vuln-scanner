"""
ConservativeRiskModel: for environments where false-positive noise must
be minimized.

Weights severity more heavily than the default model, and -- the more
significant difference -- applies a squared confidence curve instead of
a linear one, so low-confidence findings are pushed down much further
than under DefaultRiskModel. A "probable" (0.5 confidence) finding scores
a quarter of its full weighted value here, versus half under the default
model's linear curve.
"""
from __future__ import annotations

from app.risk.scoring import RiskModel


class ConservativeRiskModel(RiskModel):
    name = "conservative"
    description = (
        "Weights severity more heavily than the default model and applies "
        "a squared confidence curve, so low-confidence ('probable', not "
        "'confirmed') findings are pushed down much further than under "
        "the default linear model. Intended for environments where "
        "false-positive noise must be minimized, at the cost of "
        "potentially under-ranking real but not-yet-confirmed issues."
    )

    def weights(self) -> dict[str, float]:
        return {
            "severity": 0.40,
            "exploitability": 0.20,
            "impact": 0.25,
            "exposure": 0.15,
        }

    def confidence_multiplier(self, confidence: float) -> float:
        return confidence ** 2
