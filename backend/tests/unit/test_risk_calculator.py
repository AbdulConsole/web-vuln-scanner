from __future__ import annotations

import pytest

from app.risk.engine import RiskCalculator
from app.risk.factors import RiskFactorInput
from app.risk.models import ConservativeRiskModel, DefaultRiskModel, SeverityOnlyRiskModel


def test_default_model_max_everything_scores_exactly_100():
    # Weights sum to 1.0 and confidence is linear, so max inputs at full
    # confidence must hit exactly the top of the scale -- this is the
    # calibration check that the weight choices are self-consistent.
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=1.0, exploitability=1.0, impact=1.0, exposure=1.0, confidence=1.0)
    )
    assert result.score == pytest.approx(100.0)


def test_default_model_zero_everything_scores_exactly_zero():
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=0.0, exploitability=0.0, impact=0.0, exposure=0.0, confidence=1.0)
    )
    assert result.score == pytest.approx(0.0)


def test_default_model_known_intermediate_value():
    # Hand-calculated: (0.75*0.30 + 0.5*0.25 + 0.5*0.25 + 0.6*0.20) * 100 * 0.5
    #                = (0.225 + 0.125 + 0.125 + 0.12) * 100 * 0.5
    #                = 59.5 * 0.5 = 29.75
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=0.75, exploitability=0.5, impact=0.5, exposure=0.6, confidence=0.5)
    )
    assert result.score == pytest.approx(29.75)


def test_conservative_model_known_intermediate_value():
    # Hand-calculated: (0.75*0.40 + 0.5*0.20 + 0.5*0.25 + 0.6*0.15) * 100 * (0.5**2)
    #                = (0.30 + 0.10 + 0.125 + 0.09) * 100 * 0.25
    #                = 61.5 * 0.25 = 15.375
    calculator = RiskCalculator(ConservativeRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=0.75, exploitability=0.5, impact=0.5, exposure=0.6, confidence=0.5)
    )
    assert result.score == pytest.approx(15.375)


def test_conservative_model_scores_lower_than_default_for_same_low_confidence_input():
    factor_input = RiskFactorInput(
        severity=0.75, exploitability=0.5, impact=0.5, exposure=0.6, confidence=0.5
    )
    default_score = RiskCalculator(DefaultRiskModel()).calculate(factor_input).score
    conservative_score = RiskCalculator(ConservativeRiskModel()).calculate(factor_input).score
    assert conservative_score < default_score


def test_severity_only_model_ignores_other_factors():
    # severity=0.75 -> 75.0 regardless of everything else, since all other
    # weights are 0 and confidence is ignored entirely.
    calculator = RiskCalculator(SeverityOnlyRiskModel())
    high_other_factors = calculator.calculate(
        RiskFactorInput(severity=0.75, exploitability=1.0, impact=1.0, exposure=1.0, confidence=1.0)
    )
    low_other_factors = calculator.calculate(
        RiskFactorInput(severity=0.75, exploitability=0.0, impact=0.0, exposure=0.0, confidence=0.1)
    )
    assert high_other_factors.score == pytest.approx(75.0)
    assert low_other_factors.score == pytest.approx(75.0)


def test_breakdown_includes_one_entry_per_factor_plus_confidence_adjustment():
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=0.5, exploitability=0.5, impact=0.5, exposure=0.5, confidence=0.8)
    )
    factor_names = {b.factor_name for b in result.breakdown}
    assert factor_names == {
        "severity", "exploitability", "impact", "exposure", "confidence_adjustment",
    }


def test_breakdown_contributions_sum_to_final_score():
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=0.6, exploitability=0.4, impact=0.7, exposure=0.3, confidence=0.9)
    )
    total_contribution = sum(b.contribution for b in result.breakdown)
    assert total_contribution == pytest.approx(result.score)


def test_score_is_clamped_to_100_even_with_out_of_range_inputs():
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=2.0, exploitability=2.0, impact=2.0, exposure=2.0, confidence=2.0)
    )
    # approx, not exact equality: base_score is a sum of several
    # floating-point multiplications (0.3, 0.2 etc. aren't exactly
    # representable in binary) that could land a hair above or below 100
    # before the min(100.0, ...) clamp is applied.
    assert result.score == pytest.approx(100.0)


def test_score_is_clamped_to_zero_with_negative_inputs():
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate(
        RiskFactorInput(severity=-1.0, exploitability=-1.0, impact=-1.0, exposure=-1.0, confidence=1.0)
    )
    assert result.score == 0.0


def test_calculate_for_finding_builds_input_from_finding_fields():
    from app.models.enums import ExposureLevel, HttpMethod, Severity
    from app.models.finding import Finding

    finding = Finding(
        scan_id=None,
        url="http://example.com/",
        method=HttpMethod.GET,
        vulnerability_type="sql_injection",
        title="t",
        description="d",
        severity=Severity.HIGH,  # -> 0.75
        confidence=0.9,
        exploitability=0.7,
        impact=0.8,
        exposure=ExposureLevel.PUBLIC,  # -> 1.0
        detector_name="sql_injection",
    )
    calculator = RiskCalculator(DefaultRiskModel())
    result = calculator.calculate_for_finding(finding)

    # Hand-calculated: (0.75*0.30 + 0.7*0.25 + 0.8*0.25 + 1.0*0.20) * 100 * 0.9
    #                = (0.225 + 0.175 + 0.20 + 0.20) * 100 * 0.9
    #                = 80.0 * 0.9 = 72.0
    assert result.score == pytest.approx(72.0)
