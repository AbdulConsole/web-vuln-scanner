from __future__ import annotations

import pytest

from app.crawler.models import CrawlSummary
from app.detectors.base import BaseDetector, DetectionContext
from app.detectors.manager import (
    DetectorManager,
    clear_registry,
    discover_builtin_detectors,
    get_registry_snapshot,
    is_registered,
    list_registered_names,
    register_detector,
    restore_registry,
)
from app.models.enums import ExposureLevel, HttpMethod

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _isolated_registry():
    """Every test in this module runs against an empty registry and the
    real registry is restored afterward -- otherwise dummy test detectors
    would leak into the real registry for the rest of the test session."""
    snapshot = get_registry_snapshot()
    clear_registry()
    yield
    clear_registry()
    restore_registry(snapshot)


def _make_engine():
    from app.core.security import ScopeGuard, ScopePolicy
    from app.scanner.request_engine import RequestEngine

    guard = ScopeGuard(ScopePolicy(base_domain="example.com"))
    return RequestEngine(guard, timeout=5, rate_limit=0, concurrency=5)


def _empty_context() -> DetectionContext:
    return DetectionContext(
        engine=_make_engine(),
        crawl_summary=CrawlSummary(target_base_url="http://example.com/"),
        scan_config={},
    )


def test_register_detector_adds_to_registry():
    class Dummy(BaseDetector):
        name = "dummy_one"
        vulnerability_type = "dummy"

        async def detect(self, context):
            return []

    register_detector(Dummy)
    assert is_registered("dummy_one") is True
    assert "dummy_one" in list_registered_names()


def test_register_detector_rejects_missing_name():
    class NoName(BaseDetector):
        name = ""
        vulnerability_type = "x"

        async def detect(self, context):
            return []

    with pytest.raises(ValueError):
        register_detector(NoName)


def test_register_detector_rejects_duplicate_name():
    class First(BaseDetector):
        name = "dup"
        vulnerability_type = "a"

        async def detect(self, context):
            return []

    class Second(BaseDetector):
        name = "dup"
        vulnerability_type = "b"

        async def detect(self, context):
            return []

    register_detector(First)
    with pytest.raises(ValueError):
        register_detector(Second)


def test_re_registering_the_same_class_is_idempotent():
    class Idempotent(BaseDetector):
        name = "idempotent"
        vulnerability_type = "x"

        async def detect(self, context):
            return []

    register_detector(Idempotent)
    register_detector(Idempotent)  # same class object -- must not raise
    assert list_registered_names().count("idempotent") == 1


def test_manager_from_registry_defaults_to_all_detectors():
    class A(BaseDetector):
        name = "a"
        vulnerability_type = "ta"

        async def detect(self, context):
            return []

    class B(BaseDetector):
        name = "b"
        vulnerability_type = "tb"

        async def detect(self, context):
            return []

    register_detector(A)
    register_detector(B)

    manager = DetectorManager.from_registry(_make_engine())
    assert {d.name for d in manager.detectors} == {"a", "b"}


def test_manager_from_registry_respects_enabled_filter():
    class A(BaseDetector):
        name = "a"
        vulnerability_type = "ta"

        async def detect(self, context):
            return []

    class B(BaseDetector):
        name = "b"
        vulnerability_type = "tb"

        async def detect(self, context):
            return []

    register_detector(A)
    register_detector(B)

    manager = DetectorManager.from_registry(_make_engine(), enabled=["a"])
    assert [d.name for d in manager.detectors] == ["a"]


def test_manager_from_registry_ignores_unknown_enabled_names():
    class A(BaseDetector):
        name = "a"
        vulnerability_type = "ta"

        async def detect(self, context):
            return []

    register_detector(A)
    manager = DetectorManager.from_registry(
        _make_engine(), enabled=["a", "does_not_exist"]
    )
    assert [d.name for d in manager.detectors] == ["a"]


def test_manager_from_registry_passes_per_detector_config():
    captured = {}

    class ConfigAware(BaseDetector):
        name = "config_aware"
        vulnerability_type = "x"

        def __init__(self, engine, config=None):
            super().__init__(engine, config)
            captured["config"] = self.config

        async def detect(self, context):
            return []

    register_detector(ConfigAware)
    DetectorManager.from_registry(
        _make_engine(), detector_configs={"config_aware": {"threshold": 7}}
    )
    assert captured["config"] == {"threshold": 7}


async def test_run_all_aggregates_findings_from_multiple_detectors():
    class FindsOne(BaseDetector):
        name = "finds_one"
        vulnerability_type = "t1"

        async def detect(self, context):
            return [
                self.make_finding(
                    url="http://example.com/",
                    method=HttpMethod.GET,
                    title="t",
                    description="d",
                    confidence=0.5,
                    exploitability=0.5,
                    impact=0.5,
                    exposure=ExposureLevel.PUBLIC,
                )
            ]

    class FindsNone(BaseDetector):
        name = "finds_none"
        vulnerability_type = "t2"

        async def detect(self, context):
            return []

    manager = DetectorManager()
    manager.register_instance(FindsOne(_make_engine()))
    manager.register_instance(FindsNone(_make_engine()))

    summary = await manager.run_all(_empty_context())
    assert len(summary.findings) == 1
    assert summary.findings[0].detector_name == "finds_one"
    assert summary.errors == []


async def test_run_all_isolates_a_failing_detector():
    class Bomb(BaseDetector):
        name = "bomb"
        vulnerability_type = "t3"

        async def detect(self, context):
            raise RuntimeError("simulated detector bug")

    class Fine(BaseDetector):
        name = "fine"
        vulnerability_type = "t4"

        async def detect(self, context):
            return [
                self.make_finding(
                    url="http://example.com/",
                    method=HttpMethod.GET,
                    title="t",
                    description="d",
                    confidence=0.9,
                    exploitability=0.9,
                    impact=0.9,
                    exposure=ExposureLevel.PUBLIC,
                )
            ]

    manager = DetectorManager()
    manager.register_instance(Bomb(_make_engine()))
    manager.register_instance(Fine(_make_engine()))

    summary = await manager.run_all(_empty_context())

    assert len(summary.findings) == 1
    assert summary.findings[0].detector_name == "fine"
    assert len(summary.errors) == 1
    assert "bomb" in summary.errors[0]
    assert "simulated detector bug" in summary.errors[0]


async def test_run_all_with_no_detectors_returns_empty_summary():
    manager = DetectorManager()
    summary = await manager.run_all(_empty_context())
    assert summary.findings == []
    assert summary.errors == []


def test_discover_builtin_detectors_does_not_raise():
    # Safe to call regardless of whether concrete detector modules exist
    # (Milestone 6) or have since been added (Milestone 7's sqli.py, xss.py,
    # etc.) -- and safe to call more than once: Python caches module
    # imports, so a second call is a no-op rather than a re-registration
    # attempt. See tests/integration/test_detector_discovery.py for the
    # positive check that Milestone 7's detectors actually get discovered.
    discover_builtin_detectors()
