from __future__ import annotations

import uuid

from app.evidence.correlation import correlate_findings
from app.models.enums import ExposureLevel, FindingStatus, HttpMethod, Severity
from app.models.finding import Finding


def _make_finding(url: str, vuln_type="sqli", detector="sql_injection", risk_score=None) -> Finding:
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        url=url,
        method=HttpMethod.GET,
        vulnerability_type=vuln_type,
        title="t",
        description="d",
        severity=Severity.HIGH,
        confidence=0.8,
        exploitability=0.5,
        impact=0.5,
        exposure=ExposureLevel.PUBLIC,
        detector_name=detector,
        status=FindingStatus.OPEN,
        risk_score=risk_score,
    )
    return finding


def test_groups_same_path_different_query_values():
    findings = [
        _make_finding("http://example.com/item?id=1"),
        _make_finding("http://example.com/item?id=2"),
        _make_finding("http://example.com/item?id=3"),
    ]
    groups = correlate_findings(findings)
    assert len(groups) == 1
    assert groups[0].count == 3
    assert groups[0].path == "http://example.com/item"


def test_does_not_group_different_paths():
    findings = [
        _make_finding("http://example.com/item"),
        _make_finding("http://example.com/other"),
    ]
    groups = correlate_findings(findings)
    assert len(groups) == 2


def test_does_not_group_different_vulnerability_types_on_same_path():
    findings = [
        _make_finding("http://example.com/item?id=1", vuln_type="sqli"),
        _make_finding("http://example.com/item?id=1", vuln_type="xss_reflected"),
    ]
    groups = correlate_findings(findings)
    assert len(groups) == 2


def test_does_not_group_different_detectors_on_same_path_and_type():
    findings = [
        _make_finding("http://example.com/item?id=1", detector="detector_a"),
        _make_finding("http://example.com/item?id=1", detector="detector_b"),
    ]
    groups = correlate_findings(findings)
    assert len(groups) == 2


def test_representative_picks_highest_risk_score_when_available():
    low = _make_finding("http://example.com/item?id=1", risk_score=30.0)
    high = _make_finding("http://example.com/item?id=2", risk_score=90.0)
    groups = correlate_findings([low, high])
    assert groups[0].representative is high


def test_representative_falls_back_to_first_when_unscored():
    first = _make_finding("http://example.com/item?id=1")
    second = _make_finding("http://example.com/item?id=2")
    groups = correlate_findings([first, second])
    assert groups[0].representative is first


def test_groups_preserve_first_appearance_order():
    findings = [
        _make_finding("http://example.com/b", vuln_type="xss_reflected"),
        _make_finding("http://example.com/a", vuln_type="sqli"),
    ]
    groups = correlate_findings(findings)
    assert groups[0].path == "http://example.com/b"
    assert groups[1].path == "http://example.com/a"


def test_empty_input_returns_empty_list():
    assert correlate_findings([]) == []
