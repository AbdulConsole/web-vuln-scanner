from __future__ import annotations

import pytest

from app.risk.scoring import RiskModel, score_to_band


def test_risk_model_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        RiskModel()  # abstract weights() not implemented


def test_risk_model_default_confidence_multiplier_is_linear():
    class Concrete(RiskModel):
        name = "concrete"

        def weights(self):
            return {"severity": 1.0}

    model = Concrete()
    assert model.confidence_multiplier(0.7) == 0.7
    assert model.confidence_multiplier(1.0) == 1.0
    assert model.confidence_multiplier(0.0) == 0.0


@pytest.mark.parametrize(
    "score,expected_band",
    [
        (0.0, "informational"),
        (19.99, "informational"),
        (20.0, "low"),
        (39.99, "low"),
        (40.0, "medium"),
        (59.99, "medium"),
        (60.0, "high"),
        (79.99, "high"),
        (80.0, "critical"),
        (100.0, "critical"),
    ],
)
def test_score_to_band_boundaries(score, expected_band):
    assert score_to_band(score) == expected_band


def test_score_to_band_every_integer_0_to_100_maps_to_exactly_one_band():
    valid_bands = {"informational", "low", "medium", "high", "critical"}
    for score in range(0, 101):
        band = score_to_band(float(score))
        assert band in valid_bands


def test_score_to_band_clamps_out_of_range_values_defensively():
    assert score_to_band(-5.0) == "informational"
    assert score_to_band(150.0) == "critical"
