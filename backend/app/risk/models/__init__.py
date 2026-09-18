"""
Concrete RiskModel implementations.

Import from here rather than reaching into individual model files, so
adding a new model later is a one-line addition to this list.
"""
from __future__ import annotations

from app.risk.models.conservative import ConservativeRiskModel
from app.risk.models.default import DefaultRiskModel
from app.risk.models.severity_only import SeverityOnlyRiskModel

__all__ = ["DefaultRiskModel", "ConservativeRiskModel", "SeverityOnlyRiskModel"]
