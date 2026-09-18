"""
Risk factor normalization (Section 14).

Severity and Exposure are categorical (enums); this module maps them to
numeric [0.0, 1.0] values so they can be combined arithmetically with the
already-numeric confidence/exploitability/impact fields a detector
assigns per-finding (see app/detectors/base.py's DetectorFinding).

These mappings are deliberately simple lookup tables rather than a
shared "RiskFactor" class hierarchy: severity and exposure are fixed,
small enumerations with no behavior beyond "produce a normalized value,"
so a class per factor would add indirection without adding flexibility.
Where the spec's model calls for a "RiskFactor" abstraction, it's realized
here as these functions plus the RiskFactorInput bundle below -- see
docs/risk-model.md for the explicit mapping from the spec's vocabulary to
this codebase's classes.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import ExposureLevel, Severity

# How technically serious is the vulnerability, independent of how easy
# it is to exploit or how exposed the component is.
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.INFORMATIONAL: 0.1,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}

# How reachable is the vulnerable component to an attacker.
EXPOSURE_WEIGHTS: dict[ExposureLevel, float] = {
    ExposureLevel.PUBLIC: 1.0,
    ExposureLevel.AUTHENTICATED: 0.6,
    ExposureLevel.INTERNAL: 0.3,
    ExposureLevel.RESTRICTED: 0.15,
}


def severity_to_score(severity: Severity) -> float:
    return SEVERITY_WEIGHTS[severity]


def exposure_to_score(exposure: ExposureLevel) -> float:
    return EXPOSURE_WEIGHTS[exposure]


@dataclass(frozen=True)
class RiskFactorInput:
    """The normalized [0.0, 1.0] inputs a RiskModel combines into a score.

    Built either directly (e.g. in tests) or via
    RiskCalculator.calculate_for_finding(), which populates this from a
    Finding ORM row's stored severity/exploitability/impact/exposure/
    confidence fields.
    """

    severity: float
    exploitability: float
    impact: float
    exposure: float
    confidence: float
