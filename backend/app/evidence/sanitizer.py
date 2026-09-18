"""
Evidence sanitization (Section 12).

Every DetectorEvidence payload passes through here BEFORE being persisted
as an Evidence row (see app/evidence/collector.py). This is the single
enforcement point for "never store unnecessary secrets, credentials,
session tokens, or sensitive personal information" -- detectors themselves
are free to capture whatever raw observation supports a finding (see
app/detectors/base.py's generate_evidence(), which does no sanitization by
design); this module is what makes it safe to actually store.

Sanitizing at write-time rather than read-time is a deliberate choice: it
means no read path (API, report generation, dashboard) can accidentally
expose raw data by forgetting to redact -- there is nothing raw left in
the database to expose.
"""
from __future__ import annotations

from typing import Any

from app.core.redaction import redact
from app.detectors.base import DetectorEvidence

# Evidence payload string values longer than this are truncated. A
# detector's evidence should be a representative excerpt (e.g. the
# specific error message matched, not the entire response body) -- this is
# a backstop against a detector that captures more than it needs to.
MAX_STRING_LENGTH = 2000


def _truncate_strings(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_STRING_LENGTH:
        return value[:MAX_STRING_LENGTH] + f"...[truncated, {len(value)} chars total]"
    if isinstance(value, dict):
        return {k: _truncate_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_truncate_strings(v) for v in value]
    return value


def sanitize_evidence(evidence: DetectorEvidence) -> dict[str, Any]:
    """Return a sanitized, storage-ready payload dict for one piece of
    evidence.

    Order matters: redaction runs first (removing sensitive values
    entirely, regardless of length), then truncation bounds the size of
    whatever remains. Redacting after truncation could cut a sensitive
    value in half and leave the visible half unredacted.
    """
    redacted = redact(evidence.payload)
    return _truncate_strings(redacted)
