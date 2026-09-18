"""
Detector registry and manager (Section 9).

Adding a new detector requires exactly one thing: drop a module into
app/detectors/ with a BaseDetector subclass decorated with
@register_detector. discover_builtin_detectors() imports every module in
the package, which is what makes the decorator run -- no other file needs
to change. This is the literal implementation of Section 9's "adding a new
detector should require minimal changes" requirement.
"""
from __future__ import annotations

import asyncio
import importlib
import pkgutil
from dataclasses import dataclass, field

from app.core.logging import get_logger
from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.scanner.request_engine import RequestEngine

logger = get_logger(__name__)

_REGISTRY: dict[str, type[BaseDetector]] = {}


def register_detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    """Class decorator: adds a detector class to the global registry, keyed
    by its `name` attribute.

    Raises at import time (not at scan time) for two classes of mistake:
    a missing name, or two detectors claiming the same name -- both are
    programming errors that should fail loudly and immediately, not
    surface as a silent "one of your detectors didn't run" at scan time.
    """
    name = getattr(cls, "name", "")
    if not name:
        raise ValueError(
            f"{cls.__name__} must define a non-empty 'name' before registering"
        )
    existing = _REGISTRY.get(name)
    if existing is not None and existing is not cls:
        raise ValueError(
            f"Duplicate detector name '{name}': already registered by "
            f"{existing.__module__}.{existing.__name__}"
        )
    _REGISTRY[name] = cls
    return cls


def list_registered_names() -> list[str]:
    return list(_REGISTRY.keys())


def is_registered(name: str) -> bool:
    return name in _REGISTRY


def clear_registry() -> None:
    """Test-only helper: empties the global registry."""
    _REGISTRY.clear()


def get_registry_snapshot() -> dict[str, type[BaseDetector]]:
    """Test-only helper: returns a shallow copy for save/restore around a
    test that needs an isolated registry."""
    return dict(_REGISTRY)


def restore_registry(snapshot: dict[str, type[BaseDetector]]) -> None:
    """Test-only helper: restores a previously captured snapshot."""
    _REGISTRY.clear()
    _REGISTRY.update(snapshot)


def discover_builtin_detectors() -> None:
    """Import every sibling module in app.detectors so their
    @register_detector decorators run.

    Safe to call multiple times (Python caches imports). Safe to call when
    no concrete detector modules exist yet (Milestone 6's state): the loop
    simply does nothing, since only base.py and manager.py exist in the
    package at that point and both are explicitly skipped.
    """
    package = importlib.import_module("app.detectors")
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
        if is_pkg or module_name in {"base", "manager"}:
            continue
        importlib.import_module(f"{package.__name__}.{module_name}")


@dataclass
class DetectionRunSummary:
    findings: list[DetectorFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DetectorManager:
    """Holds a set of instantiated detectors and runs them against a
    DetectionContext, isolating failures per-detector."""

    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}

    def register_instance(self, detector: BaseDetector) -> None:
        self._detectors[detector.name] = detector

    @property
    def detectors(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def get(self, name: str) -> BaseDetector | None:
        return self._detectors.get(name)

    @classmethod
    def from_registry(
        cls,
        engine: RequestEngine,
        *,
        enabled: list[str] | None = None,
        detector_configs: dict[str, dict] | None = None,
    ) -> DetectorManager:
        """Build a manager from every globally registered detector class.

        enabled=None (or omitted) means "all registered detectors" --
        matching ScanConfig.enabled_detectors' documented semantics
        (Milestone 3: an empty list means all detectors). Unknown names in
        `enabled` are silently ignored rather than raising, since a target
        created against an older detector set shouldn't break when a
        detector is later renamed or removed.
        """
        manager = cls()
        detector_configs = detector_configs or {}
        for name, detector_cls in _REGISTRY.items():
            if enabled is not None and len(enabled) > 0 and name not in enabled:
                continue
            instance = detector_cls(engine, config=detector_configs.get(name))
            manager.register_instance(instance)
        return manager

    async def run_all(
        self, context: DetectionContext, *, concurrency: int = 5
    ) -> DetectionRunSummary:
        """Run every registered detector concurrently (bounded by
        `concurrency`), collecting findings. A detector that raises is
        caught and recorded as an error string rather than propagated --
        one buggy or third-party detector must not prevent every other
        detector's findings from being collected.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def run_one(
            detector: BaseDetector,
        ) -> tuple[str, list[DetectorFinding], str | None]:
            async with semaphore:
                try:
                    result = await detector.detect(context)
                    return detector.name, result, None
                except Exception as exc:  # noqa: BLE001 -- deliberate: isolate per-detector failures
                    logger.exception(
                        "Detector raised an exception",
                        extra={"context": {"detector": detector.name}},
                    )
                    return detector.name, [], str(exc)

        results = await asyncio.gather(*(run_one(d) for d in self.detectors))

        findings: list[DetectorFinding] = []
        errors: list[str] = []
        for name, detector_findings, error in results:
            findings.extend(detector_findings)
            if error is not None:
                errors.append(f"{name}: {error}")

        return DetectionRunSummary(findings=findings, errors=errors)
