"""
SeverityOnlyRiskModel: a deliberately naive baseline for research
comparison (Section 30).

Section 30 asks the architecture to support comparing "severity-only
prioritization VS risk-based prioritization" on the same finding set, to
demonstrate what the risk-based approach actually adds. This model is
that baseline: it scores purely by severity and ignores exploitability,
impact, exposure, and confidence entirely. It is not intended as a
production scoring strategy -- see docs/risk-model.md for the comparison
methodology this enables.
"""
from __future__ import annotations

from app.risk.scoring import RiskModel


class SeverityOnlyRiskModel(RiskModel):
    name = "severity_only"
    description = (
        "Research-comparison baseline: scores purely by severity, "
        "ignoring exploitability, impact, exposure, and confidence. "
        "Exists to demonstrate what risk-based prioritization adds over "
        "a traditional severity-only approach on the same finding set."
    )

    def weights(self) -> dict[str, float]:
        return {
            "severity": 1.0,
            "exploitability": 0.0,
            "impact": 0.0,
            "exposure": 0.0,
        }

    def confidence_multiplier(self, confidence: float) -> float:
        return 1.0  # confidence is also ignored, by design
