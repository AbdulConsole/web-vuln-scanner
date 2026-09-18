"""
Risk assessment (Section 13) -- the project's core research contribution.

- factors.py: normalizes categorical Severity/Exposure into [0,1] values.
- scoring.py: the RiskModel interface, FactorContribution/RiskScoreResult
  types, and the 0-100 -> qualitative band mapping.
- models/: concrete RiskModel strategies (Default, Conservative,
  SeverityOnly), swappable without touching scoring or persistence code.
- engine.py: RiskCalculator (pure arithmetic) and RiskEngine (persists
  scores + breakdowns for a scan's findings).
- prioritizer.py (Milestone 10): ranks scored findings and generates
  human-readable explanations for each ranking.
"""
from __future__ import annotations

from app.risk.engine import RiskCalculator, RiskEngine
from app.risk.factors import RiskFactorInput, exposure_to_score, severity_to_score
from app.risk.models import ConservativeRiskModel, DefaultRiskModel, SeverityOnlyRiskModel
from app.risk.prioritizer import PrioritizedFinding, Prioritizer
from app.risk.scoring import FactorContribution, RiskModel, RiskScoreResult, score_to_band

__all__ = [
    "RiskCalculator",
    "RiskEngine",
    "RiskFactorInput",
    "severity_to_score",
    "exposure_to_score",
    "RiskModel",
    "RiskScoreResult",
    "FactorContribution",
    "score_to_band",
    "DefaultRiskModel",
    "ConservativeRiskModel",
    "SeverityOnlyRiskModel",
    "Prioritizer",
    "PrioritizedFinding",
]
