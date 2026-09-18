"""
Proves the Milestone 6 auto-discovery mechanism actually works against the
real Milestone 7 detector modules -- the two milestones' tests are kept
separate (unit tests use isolated fake registries), so this is the one
place that exercises the real, production `_REGISTRY`.

Deliberately does NOT clear/restore the registry around this test: once
discovered, detectors are expected to stay registered for the process's
lifetime, and Python caches module imports, so re-running discovery after
clearing the registry would not be a meaningful thing to test (see the
note in tests/unit/test_detector_manager.py).
"""
from __future__ import annotations

from app.detectors.manager import discover_builtin_detectors, list_registered_names

EXPECTED_DETECTOR_NAMES = {
    "sql_injection",
    "xss_reflected",
    "xss_stored",
    "security_headers",
    "information_disclosure",
    "csrf",
    "access_control",
}


def test_all_milestone_7_detectors_are_discovered():
    discover_builtin_detectors()
    registered = set(list_registered_names())
    missing = EXPECTED_DETECTOR_NAMES - registered
    assert not missing, f"detectors not discovered: {missing}"


def test_calling_discovery_twice_does_not_raise():
    discover_builtin_detectors()
    discover_builtin_detectors()  # must be idempotent
