"""
Finding/Evidence persistence (Section 11/12).

Translates the detector layer's plain dataclasses (DetectorFinding,
DetectorEvidence -- see app/detectors/base.py) into ORM rows, applying
evidence sanitization along the way. This is the one place the
detector/crawler layer meets the database: detectors themselves have zero
ORM/session dependency, which is what keeps them unit-testable without a
database (see tests/unit/test_*_detector.py).
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.detectors.base import DetectorFinding
from app.evidence.sanitizer import sanitize_evidence
from app.models.finding import Evidence, Finding

logger = get_logger(__name__)


class EvidenceCollector:
    """Persists detector output for one scan.

    Exact-duplicate suppression (Section 17) happens here: if two
    DetectorFinding objects handed to persist_all() describe the same
    (vulnerability_type, url, parameter, detector_name), only the first is
    persisted. This is a defensive backstop, not the primary
    deduplication mechanism -- the crawler/detector pipeline already
    avoids generating true duplicates via collect_param_targets'
    deduplication (Milestone 7), but a future or third-party detector
    could still produce one, and this makes that harmless rather than
    something that silently inflates a scan's finding count.

    Similar-but-distinct findings (e.g. the same SQLi pattern found on
    /item?id=1 and /item?id=2) are intentionally NOT collapsed here --
    each is a real, independently-verified finding and is persisted as
    its own row for audit completeness. Grouping those for display
    purposes is a separate, non-destructive concern handled by
    app.evidence.correlation, which operates on already-persisted Finding
    rows without changing what was stored.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def persist_finding(
        self, scan_id: uuid.UUID, detector_finding: DetectorFinding
    ) -> Finding:
        finding = Finding(
            scan_id=scan_id,
            url=detector_finding.url,
            method=detector_finding.method,
            parameter=detector_finding.parameter,
            vulnerability_type=detector_finding.vulnerability_type,
            title=detector_finding.title,
            description=detector_finding.description,
            severity=detector_finding.severity,
            confidence=detector_finding.confidence,
            exploitability=detector_finding.exploitability,
            impact=detector_finding.impact,
            exposure=detector_finding.exposure,
            remediation=detector_finding.remediation,
            references=list(detector_finding.references),
            detector_name=detector_finding.detector_name,
        )
        self.session.add(finding)
        await self.session.flush()  # populate finding.id for the Evidence FK

        for raw_evidence in detector_finding.evidence:
            sanitized_payload = sanitize_evidence(raw_evidence)
            self.session.add(
                Evidence(
                    finding_id=finding.id,
                    kind=raw_evidence.kind,
                    sanitized_payload=sanitized_payload,
                )
            )

        await self.session.flush()
        return finding

    async def persist_all(
        self, scan_id: uuid.UUID, detector_findings: Sequence[DetectorFinding]
    ) -> list[Finding]:
        seen: set[tuple[str, str, str | None, str]] = set()
        persisted: list[Finding] = []
        duplicates_suppressed = 0

        for detector_finding in detector_findings:
            key = (
                detector_finding.vulnerability_type,
                detector_finding.url,
                detector_finding.parameter,
                detector_finding.detector_name,
            )
            if key in seen:
                duplicates_suppressed += 1
                continue
            seen.add(key)
            persisted.append(await self.persist_finding(scan_id, detector_finding))

        if duplicates_suppressed:
            logger.info(
                "Suppressed exact-duplicate findings",
                extra={
                    "context": {
                        "scan_id": str(scan_id),
                        "duplicates_suppressed": duplicates_suppressed,
                    }
                },
            )

        return persisted
