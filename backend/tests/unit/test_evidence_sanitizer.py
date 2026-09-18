from __future__ import annotations

from app.detectors.base import DetectorEvidence
from app.evidence.sanitizer import MAX_STRING_LENGTH, sanitize_evidence


def test_sanitize_redacts_sensitive_fields():
    evidence = DetectorEvidence(
        kind="request_snapshot",
        payload={"url": "http://example.com/", "cookie": "session=abc123"},
    )
    sanitized = sanitize_evidence(evidence)
    assert sanitized["url"] == "http://example.com/"
    assert sanitized["cookie"] == "***REDACTED***"


def test_sanitize_truncates_long_strings():
    long_value = "A" * (MAX_STRING_LENGTH + 500)
    evidence = DetectorEvidence(kind="response_body", payload={"body": long_value})
    sanitized = sanitize_evidence(evidence)
    assert len(sanitized["body"]) < len(long_value)
    assert sanitized["body"].startswith("A" * 100)
    assert "truncated" in sanitized["body"]


def test_sanitize_leaves_short_strings_untouched():
    evidence = DetectorEvidence(kind="reflection", payload={"payload": "short value"})
    sanitized = sanitize_evidence(evidence)
    assert sanitized["payload"] == "short value"


def test_sanitize_redacts_before_truncating():
    """A sensitive value that's also very long must be fully redacted, not
    truncated down to a half-redacted fragment."""
    long_secret = "s3cr3t" * 1000
    evidence = DetectorEvidence(kind="x", payload={"api_key": long_secret})
    sanitized = sanitize_evidence(evidence)
    assert sanitized["api_key"] == "***REDACTED***"


def test_sanitize_handles_nested_and_list_payloads():
    evidence = DetectorEvidence(
        kind="multi_step",
        payload={
            "steps": [
                {"url": "http://example.com/1", "password": "hunter2"},
                {"url": "http://example.com/2", "password": "hunter3"},
            ]
        },
    )
    sanitized = sanitize_evidence(evidence)
    assert sanitized["steps"][0]["password"] == "***REDACTED***"
    assert sanitized["steps"][1]["password"] == "***REDACTED***"
    assert sanitized["steps"][0]["url"] == "http://example.com/1"


def test_sanitize_returns_plain_dict_not_evidence_object():
    evidence = DetectorEvidence(kind="x", payload={"a": 1})
    result = sanitize_evidence(evidence)
    assert isinstance(result, dict)
