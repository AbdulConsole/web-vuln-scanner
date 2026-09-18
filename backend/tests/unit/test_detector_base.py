from __future__ import annotations

import pytest

from app.detectors.base import BaseDetector, DetectorEvidence, DetectorFinding
from app.models.enums import ExposureLevel, HttpMethod, Severity


class _ConcreteDetector(BaseDetector):
    name = "test_concrete_detector"
    vulnerability_type = "test_vuln"
    description = "A detector used only in tests."
    default_severity = Severity.HIGH

    async def detect(self, context):
        return []


def _make_engine():
    from app.core.security import ScopeGuard, ScopePolicy
    from app.scanner.request_engine import RequestEngine

    guard = ScopeGuard(ScopePolicy(base_domain="example.com"))
    return RequestEngine(guard, timeout=5, rate_limit=0, concurrency=5)


def test_detector_finding_accepts_valid_bounds():
    finding = DetectorFinding(
        url="http://example.com/",
        method=HttpMethod.GET,
        vulnerability_type="xss",
        title="t",
        description="d",
        severity=Severity.LOW,
        confidence=0.0,
        exploitability=1.0,
        impact=0.5,
        exposure=ExposureLevel.PUBLIC,
        detector_name="d",
    )
    assert finding.confidence == 0.0
    assert finding.exploitability == 1.0


@pytest.mark.parametrize("field_name", ["confidence", "exploitability", "impact"])
def test_detector_finding_rejects_out_of_range_values(field_name):
    kwargs = dict(
        url="http://example.com/",
        method=HttpMethod.GET,
        vulnerability_type="xss",
        title="t",
        description="d",
        severity=Severity.LOW,
        confidence=0.5,
        exploitability=0.5,
        impact=0.5,
        exposure=ExposureLevel.PUBLIC,
        detector_name="d",
    )
    kwargs[field_name] = 1.5
    with pytest.raises(ValueError):
        DetectorFinding(**kwargs)


def test_base_detector_requires_nonempty_name():
    class NoName(BaseDetector):
        name = ""
        vulnerability_type = "x"

        async def detect(self, context):
            return []

    with pytest.raises(ValueError):
        NoName(_make_engine())


def test_base_detector_requires_nonempty_vulnerability_type():
    class NoType(BaseDetector):
        name = "no_type"
        vulnerability_type = ""

        async def detect(self, context):
            return []

    with pytest.raises(ValueError):
        NoType(_make_engine())


def test_base_detector_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        BaseDetector(_make_engine())  # abstract detect() not implemented


def test_generate_evidence_wraps_payload():
    detector = _ConcreteDetector(_make_engine())
    evidence = detector.generate_evidence("response_diff", {"note": "value"})
    assert isinstance(evidence, DetectorEvidence)
    assert evidence.kind == "response_diff"
    assert evidence.payload == {"note": "value"}


def test_make_finding_fills_in_detector_identity():
    detector = _ConcreteDetector(_make_engine())
    finding = detector.make_finding(
        url="http://example.com/login",
        method=HttpMethod.POST,
        title="Possible issue",
        description="desc",
        confidence=0.6,
        exploitability=0.4,
        impact=0.7,
        exposure=ExposureLevel.PUBLIC,
    )
    assert finding.vulnerability_type == "test_vuln"
    assert finding.detector_name == "test_concrete_detector"
    assert finding.severity == Severity.HIGH  # falls back to default_severity


def test_make_finding_allows_overriding_severity():
    detector = _ConcreteDetector(_make_engine())
    finding = detector.make_finding(
        url="http://example.com/",
        method=HttpMethod.GET,
        title="t",
        description="d",
        confidence=0.5,
        exploitability=0.5,
        impact=0.5,
        exposure=ExposureLevel.PUBLIC,
        severity=Severity.CRITICAL,
    )
    assert finding.severity == Severity.CRITICAL


def test_config_defaults_to_empty_dict():
    detector = _ConcreteDetector(_make_engine())
    assert detector.config == {}

    detector2 = _ConcreteDetector(_make_engine(), config={"threshold": 3})
    assert detector2.config == {"threshold": 3}
