"""
Evidence and finding persistence (Sections 11/12/17).

- sanitizer.py: redacts/truncates a detector's raw evidence before storage.
- collector.py: translates DetectorFinding objects into persisted
  Finding/Evidence ORM rows, applying sanitization and exact-duplicate
  suppression along the way.
- correlation.py: groups already-persisted, genuinely-distinct findings
  that likely share an underlying cause, for reporting purposes only.
"""
from __future__ import annotations

from app.evidence.collector import EvidenceCollector
from app.evidence.correlation import FindingGroup, correlate_findings
from app.evidence.sanitizer import sanitize_evidence

__all__ = [
    "EvidenceCollector",
    "FindingGroup",
    "correlate_findings",
    "sanitize_evidence",
]
