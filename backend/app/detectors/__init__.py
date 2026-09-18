"""
Detector plugin framework (Section 9).

Concrete detectors (Milestone 7) live in sibling modules in this package
and register themselves via the @register_detector decorator at import
time. discover_builtin_detectors() (called once at scan startup, or by
tests) imports every module in this package so that registration actually
happens -- no other file needs to know a new detector exists.
"""
from __future__ import annotations

from app.detectors.base import (
    BaseDetector,
    DetectionContext,
    DetectorEvidence,
    DetectorFinding,
)
from app.detectors.manager import (
    DetectionRunSummary,
    DetectorManager,
    discover_builtin_detectors,
    register_detector,
)

__all__ = [
    "BaseDetector",
    "DetectionContext",
    "DetectorEvidence",
    "DetectorFinding",
    "DetectorManager",
    "DetectionRunSummary",
    "discover_builtin_detectors",
    "register_detector",
]
