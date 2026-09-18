"""
Detector plugin interface (Section 9).

A concrete detector (Milestone 7) subclasses BaseDetector, declares its
identity as class attributes, and implements detect(). Detectors are
handed a DetectionContext (the crawler's attack surface plus the shared
RequestEngine) and return DetectorFinding objects -- plain dataclasses,
not ORM rows, for the same reason the crawler's models aren't ORM rows:
detectors should be testable with zero database dependency.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.crawler.models import CrawledUrl, CrawlSummary, DiscoveredForm, DiscoveredParameter
from app.models.enums import ExposureLevel, HttpMethod, Severity
from app.scanner.request_engine import RequestEngine


@dataclass(frozen=True)
class DetectorEvidence:
    """Raw evidence produced by a detector.

    NOT sanitized here -- app.evidence.sanitizer (Milestone 8) redacts
    this before it is ever persisted. Detectors should feel free to
    include whatever observation supports the finding (response snippets,
    diffed content, headers observed); sanitization is a downstream,
    storage-time concern, not a detector-authoring concern.
    """

    kind: str
    payload: dict[str, Any]


@dataclass
class DetectorFinding:
    """A candidate vulnerability finding, prior to persistence and prior to
    risk scoring. Fields mirror app.models.finding.Finding closely by
    design -- Milestone 8/9 will map one to the other -- but this type has
    no database dependency.
    """

    url: str
    method: HttpMethod
    vulnerability_type: str
    title: str
    description: str
    severity: Severity
    confidence: float
    exploitability: float
    impact: float
    exposure: ExposureLevel
    detector_name: str
    parameter: str | None = None
    evidence: list[DetectorEvidence] = field(default_factory=list)
    remediation: str | None = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Same [0.0, 1.0] invariant as the DB CHECK constraints on Finding
        # (Milestone 2) -- enforced here too so a detector bug fails fast,
        # at the point it was introduced, rather than at DB insert time.
        for field_name, value in (
            ("confidence", self.confidence),
            ("exploitability", self.exploitability),
            ("impact", self.impact),
        ):
            if not (0.0 <= value <= 1.0):
                raise ValueError(
                    f"{field_name} must be within [0.0, 1.0], got {value!r}"
                )


@dataclass
class DetectionContext:
    """Everything a detector needs to run, bundled together so detect()
    has a single, stable parameter regardless of how many context fields
    grow over time."""

    engine: RequestEngine
    crawl_summary: CrawlSummary
    scan_config: dict[str, Any] = field(default_factory=dict)
    # Best-effort default exposure classification for this scan, set by
    # whoever constructs the context (e.g. Authenticated if the scan used
    # AuthConfig, Public otherwise). Individual detectors may override this
    # per-finding when they have better information (e.g. a path that is
    # itself clearly admin-only).
    default_exposure: ExposureLevel = ExposureLevel.PUBLIC
    # A second engine carrying NO auth material, supplied only when the
    # scan itself is authenticated. Lets the access-control detector
    # compare authenticated vs. unauthenticated responses. None means "no
    # comparison is possible" -- see detectors/access_control.py, which
    # returns no findings rather than guessing when this is absent.
    unauthenticated_engine: RequestEngine | None = None

    @property
    def urls(self) -> list[CrawledUrl]:
        return self.crawl_summary.urls

    @property
    def forms(self) -> list[DiscoveredForm]:
        return self.crawl_summary.discovered_forms

    @property
    def parameters(self) -> list[DiscoveredParameter]:
        return self.crawl_summary.discovered_parameters


class BaseDetector(ABC):
    """Every concrete detector subclasses this and sets the ClassVars
    below. Detector identity lives on the class (not an instance) because
    the registry (manager.py) keys on it before any instance exists."""

    name: ClassVar[str] = ""
    vulnerability_type: ClassVar[str] = ""
    description: ClassVar[str] = ""
    default_severity: ClassVar[Severity] = Severity.MEDIUM

    def __init__(self, engine: RequestEngine, config: dict[str, Any] | None = None):
        if not self.name:
            raise ValueError(
                f"{type(self).__name__} must define a non-empty 'name' class attribute"
            )
        if not self.vulnerability_type:
            raise ValueError(
                f"{type(self).__name__} must define a non-empty "
                f"'vulnerability_type' class attribute"
            )
        self.engine = engine
        self.config = config or {}

    @abstractmethod
    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        """Run this detector's checks and return any findings.

        Must not raise for "no vulnerability found" -- return an empty
        list. Raising is reserved for genuine detector bugs; the
        DetectorManager catches and isolates those so one broken detector
        can't abort detection for every other detector (see manager.py).
        """
        raise NotImplementedError

    def generate_evidence(self, kind: str, payload: dict[str, Any]) -> DetectorEvidence:
        """Build a DetectorEvidence record. The default implementation just
        wraps the payload; subclasses may override to shape evidence
        differently, but should not attempt sanitization here -- that's
        Milestone 8's job, applied uniformly across all detectors."""
        return DetectorEvidence(kind=kind, payload=payload)

    def make_finding(
        self,
        *,
        url: str,
        method: HttpMethod,
        title: str,
        description: str,
        confidence: float,
        exploitability: float,
        impact: float,
        exposure: ExposureLevel,
        parameter: str | None = None,
        severity: Severity | None = None,
        evidence: list[DetectorEvidence] | None = None,
        remediation: str | None = None,
        references: list[str] | None = None,
    ) -> DetectorFinding:
        """Convenience constructor that fills in vulnerability_type and
        detector_name from this detector's class attributes, so concrete
        detectors (Milestone 7) don't repeat them on every finding."""
        return DetectorFinding(
            url=url,
            method=method,
            vulnerability_type=self.vulnerability_type,
            title=title,
            description=description,
            severity=severity or self.default_severity,
            confidence=confidence,
            exploitability=exploitability,
            impact=impact,
            exposure=exposure,
            detector_name=self.name,
            parameter=parameter,
            evidence=evidence or [],
            remediation=remediation,
            references=references or [],
        )
