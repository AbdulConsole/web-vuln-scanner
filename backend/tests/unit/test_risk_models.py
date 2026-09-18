from __future__ import annotations

import pytest

from app.risk.models import ConservativeRiskModel, DefaultRiskModel, SeverityOnlyRiskModel


@pytest.mark.parametrize(
    "model_cls",
    [DefaultRiskModel, ConservativeRiskModel, SeverityOnlyRiskModel],
)
def test_weights_sum_to_one(model_cls):
    model = model_cls()
    total = sum(model.weights().values())
    assert total == pytest.approx(1.0)


def test_default_model_uses_linear_confidence():
    model = DefaultRiskModel()
    assert model.confidence_multiplier(0.5) == 0.5


def test_conservative_model_squares_confidence():
    model = ConservativeRiskModel()
    assert model.confidence_multiplier(0.5) == pytest.approx(0.25)
    assert model.confidence_multiplier(1.0) == pytest.approx(1.0)
    assert model.confidence_multiplier(0.0) == pytest.approx(0.0)


def test_conservative_model_punishes_low_confidence_harder_than_default():
    default_mult = DefaultRiskModel().confidence_multiplier(0.5)
    conservative_mult = ConservativeRiskModel().confidence_multiplier(0.5)
    assert conservative_mult < default_mult


def test_severity_only_model_weights_only_severity():
    weights = SeverityOnlyRiskModel().weights()
    assert weights["severity"] == 1.0
    assert weights["exploitability"] == 0.0
    assert weights["impact"] == 0.0
    assert weights["exposure"] == 0.0


def test_severity_only_model_ignores_confidence():
    model = SeverityOnlyRiskModel()
    assert model.confidence_multiplier(0.0) == 1.0
    assert model.confidence_multiplier(0.5) == 1.0
    assert model.confidence_multiplier(1.0) == 1.0


def test_each_model_has_a_unique_name():
    names = {DefaultRiskModel().name, ConservativeRiskModel().name, SeverityOnlyRiskModel().name}
    assert len(names) == 3


def test_each_model_has_a_nonempty_description():
    for model_cls in [DefaultRiskModel, ConservativeRiskModel, SeverityOnlyRiskModel]:
        assert len(model_cls().description) > 20
