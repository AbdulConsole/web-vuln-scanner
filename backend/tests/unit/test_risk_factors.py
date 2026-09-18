from __future__ import annotations

import pytest

from app.models.enums import ExposureLevel, Severity
from app.risk.factors import RiskFactorInput, exposure_to_score, severity_to_score


@pytest.mark.parametrize(
    "severity,expected",
    [
        (Severity.INFORMATIONAL, 0.1),
        (Severity.LOW, 0.3),
        (Severity.MEDIUM, 0.5),
        (Severity.HIGH, 0.75),
        (Severity.CRITICAL, 1.0),
    ],
)
def test_severity_to_score(severity, expected):
    assert severity_to_score(severity) == expected


@pytest.mark.parametrize(
    "exposure,expected",
    [
        (ExposureLevel.PUBLIC, 1.0),
        (ExposureLevel.AUTHENTICATED, 0.6),
        (ExposureLevel.INTERNAL, 0.3),
        (ExposureLevel.RESTRICTED, 0.15),
    ],
)
def test_exposure_to_score(exposure, expected):
    assert exposure_to_score(exposure) == expected


def test_severity_scores_are_monotonically_increasing_with_seriousness():
    ordered = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    scores = [severity_to_score(s) for s in ordered]
    assert scores == sorted(scores)


def test_exposure_scores_are_monotonically_decreasing_with_restriction():
    ordered = [ExposureLevel.PUBLIC, ExposureLevel.AUTHENTICATED, ExposureLevel.INTERNAL, ExposureLevel.RESTRICTED]
    scores = [exposure_to_score(e) for e in ordered]
    assert scores == sorted(scores, reverse=True)


def test_risk_factor_input_holds_provided_values():
    factor_input = RiskFactorInput(
        severity=0.75, exploitability=0.5, impact=0.6, exposure=1.0, confidence=0.9
    )
    assert factor_input.severity == 0.75
    assert factor_input.exploitability == 0.5
    assert factor_input.impact == 0.6
    assert factor_input.exposure == 1.0
    assert factor_input.confidence == 0.9
