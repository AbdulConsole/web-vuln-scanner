"""
Finding correlation (Section 17).

Deliberately separate from exact-duplicate suppression
(app.evidence.collector.EvidenceCollector), which prevents true duplicates
from ever being persisted. This module does the opposite kind of work: it
takes findings that are all genuinely real and already persisted, and
groups the ones that likely represent the same underlying issue on the
same code path (e.g. the same SQLi pattern found on /item?id=1,
/item?id=2, /item?id=3) so a report or dashboard can show "1 issue, 3
occurrences" instead of 3 unrelated-looking rows.

This never changes what's in the database -- every Finding row persisted
by the collector stays exactly as it is, for audit completeness. Grouping
is purely a presentation-time transformation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.models.finding import Finding


def _path_key(url: str) -> str:
    """Reduce a URL to scheme+host+path (drop the query string) so
    /item?id=1 and /item?id=2 correlate to the same key."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


@dataclass
class FindingGroup:
    """Findings that likely represent the same underlying issue: same
    detector, same vulnerability type, same URL path (query string
    ignored)."""

    vulnerability_type: str
    detector_name: str
    path: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def representative(self) -> Finding | None:
        """The single most useful finding to show as the group's face: the
        highest-risk-scored one if any are scored yet, otherwise simply
        the first one encountered."""
        if not self.findings:
            return None
        scored = [f for f in self.findings if f.risk_score is not None]
        if scored:
            return max(scored, key=lambda f: f.risk_score)
        return self.findings[0]


def correlate_findings(findings: list[Finding]) -> list[FindingGroup]:
    """Group findings by (vulnerability_type, detector_name, url path).

    Groups are returned in order of first appearance in `findings`, so
    callers that pass in priority-ordered findings get priority-ordered
    groups.
    """
    groups: dict[tuple[str, str, str], FindingGroup] = {}
    order: list[tuple[str, str, str]] = []

    for finding in findings:
        path = _path_key(finding.url)
        key = (finding.vulnerability_type, finding.detector_name, path)
        if key not in groups:
            groups[key] = FindingGroup(
                vulnerability_type=finding.vulnerability_type,
                detector_name=finding.detector_name,
                path=path,
            )
            order.append(key)
        groups[key].findings.append(finding)

    return [groups[key] for key in order]
