"""DefaultRiskModel: the scanner's baseline scoring strategy (Section 13)."""
from __future__ import annotations

from app.risk.scoring import RiskModel


class DefaultRiskModel(RiskModel):
    name = "default"
    description = (
        "Baseline weighting: severity and exploitability weighted most "
        "heavily, impact equally with exploitability, exposure least. "
        "Confidence applied as a linear multiplier on the weighted base "
        "score. A finding with every factor at maximum and full "
        "confidence scores exactly 100."
    )

    def weights(self) -> dict[str, float]:
        return {
            "severity": 0.30,
            "exploitability": 0.25,
            "impact": 0.25,
            "exposure": 0.20,
        }
