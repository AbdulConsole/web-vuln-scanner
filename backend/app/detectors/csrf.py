"""
CSRF detector (Section 10.F).

This is a heuristic, evidence-based check only: it looks for the presence
of a plausibly-named anti-CSRF token field on state-changing forms. It
does NOT attempt to submit a form without a token to see if the server
accepts it -- doing so would mean actually performing the state-changing
action to "confirm" the vulnerability, which conflicts with Section 1's
non-destructive-by-default requirement. As a result this detector only
ever reports "Not detected" (no finding) or "Potential issue" (a finding
with explicitly heuristic-limited confidence); it never reports
"Confirmed", stated here as a scope limitation rather than implemented
unsafely.
"""
from __future__ import annotations

from typing import Any

from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.detectors.manager import register_detector
from app.detectors.signatures import CSRF_TOKEN_FIELD_HINTS
from app.models.enums import HttpMethod, Severity

_STATE_CHANGING_METHODS = {
    HttpMethod.POST,
    HttpMethod.PUT,
    HttpMethod.PATCH,
    HttpMethod.DELETE,
}


@register_detector
class CsrfDetector(BaseDetector):
    name = "csrf"
    vulnerability_type = "csrf"
    description = (
        "Flags state-changing forms that appear to lack an anti-CSRF "
        "token field, based on field-name heuristics."
    )
    default_severity = Severity.MEDIUM

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for crawled in context.urls:
            for form in crawled.forms:
                if form.method not in _STATE_CHANGING_METHODS:
                    continue
                if self._has_csrf_token_field(form):
                    continue  # "Not detected" -- token field present

                evidence = self.generate_evidence(
                    "missing_csrf_token_field",
                    {
                        "form_action": form.action,
                        "hosting_url": crawled.url,
                        "field_names": [f["name"] for f in form.inputs],
                    },
                )
                findings.append(
                    self.make_finding(
                        url=form.action,
                        method=form.method,
                        title="Form may be missing CSRF protection",
                        description=(
                            f"The state-changing form at '{form.action}' (found "
                            f"on '{crawled.url}') has no field matching common "
                            f"anti-CSRF token naming conventions. This is a "
                            f"heuristic, potential-issue finding: the "
                            f"application may validate CSRF protection through "
                            f"a mechanism this check cannot see (e.g. a "
                            f"SameSite=Strict session cookie, custom header "
                            f"checks, or a token embedded outside the HTML "
                            f"form). Manual verification is required before "
                            f"treating this as confirmed."
                        ),
                        confidence=0.35,
                        exploitability=0.35,
                        impact=0.5,
                        exposure=context.default_exposure,
                        severity=Severity.MEDIUM,
                        evidence=[evidence],
                        remediation=(
                            "Implement synchronizer-token CSRF protection (a "
                            "per-session or per-request token embedded in a "
                            "hidden form field and validated server-side), or "
                            "rely on SameSite=Strict/Lax session cookies plus "
                            "Origin/Referer validation for state-changing "
                            "requests."
                        ),
                        references=["https://owasp.org/www-community/attacks/csrf"],
                    )
                )

        return findings

    def _has_csrf_token_field(self, form: Any) -> bool:
        for field_def in form.inputs:
            name = (field_def.get("name") or "").lower()
            if any(hint in name for hint in CSRF_TOKEN_FIELD_HINTS):
                return True
        return False
