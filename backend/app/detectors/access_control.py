"""
Broken Access Control detector (Section 10.G).

LIMITATION, stated plainly: true horizontal/vertical privilege-escalation
testing requires comparing behavior between two distinct authenticated
identities (e.g. a low-privilege and a high-privilege account), which the
current Target/AuthConfig schema (Milestone 3) does not yet support -- it
holds exactly one credential set. Adding multi-identity support is a
schema and scan-orchestration change; this detector does not attempt to
work around that gap unsafely.

What IS implemented: a safe, non-destructive comparison between an
authenticated and an unauthenticated GET request to URLs whose path looks
like it should require authentication (heuristic name matching only --
"admin", "settings", "account", etc.). If the unauthenticated request also
succeeds and doesn't look like a login page, that is a signal -- not
proof -- that the endpoint may lack real access control.

This detector runs only when the caller supplies
context.unauthenticated_engine; without it, there's nothing to compare
against, so it returns no findings rather than guessing.
"""
from __future__ import annotations

from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.detectors.manager import register_detector
from app.detectors.signatures import SENSITIVE_PATH_HINTS
from app.models.enums import HttpMethod, Severity

_LOGIN_PAGE_MARKERS = ["log in", "login", "sign in", "password", "authentication required"]


@register_detector
class AccessControlDetector(BaseDetector):
    name = "access_control"
    vulnerability_type = "broken_access_control"
    description = (
        "Heuristically compares authenticated vs. unauthenticated access "
        "to URLs whose path suggests they should require authentication."
    )
    default_severity = Severity.HIGH

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        if context.unauthenticated_engine is None:
            return []  # nothing to compare against -- see module docstring

        findings: list[DetectorFinding] = []
        candidates = [
            u
            for u in context.urls
            if u.status_code == 200
            and any(hint in u.url.lower() for hint in SENSITIVE_PATH_HINTS)
        ]

        for crawled in candidates:
            unauth_response = await context.unauthenticated_engine.get(crawled.url)
            if not unauth_response.ok or unauth_response.status_code != 200:
                continue  # correctly redirected/blocked -- no finding
            if not unauth_response.text:
                continue

            lowered = unauth_response.text.lower()
            if any(marker in lowered for marker in _LOGIN_PAGE_MARKERS):
                continue  # looks like a login page was served -- protected

            evidence = self.generate_evidence(
                "unauthenticated_access_succeeded",
                {
                    "url": crawled.url,
                    "unauthenticated_status": unauth_response.status_code,
                    "response_length": len(unauth_response.text),
                },
            )
            findings.append(
                self.make_finding(
                    url=crawled.url,
                    method=HttpMethod.GET,
                    title="Possible missing access control",
                    description=(
                        f"'{crawled.url}' returned a 200 response with no "
                        f"apparent login/authentication prompt when requested "
                        f"without credentials, despite its path suggesting it "
                        f"should require authentication. This is a heuristic "
                        f"signal based on URL naming, not confirmed proof the "
                        f"page contains sensitive functionality or data -- "
                        f"manual verification is required."
                    ),
                    confidence=0.4,
                    exploitability=0.5,
                    impact=0.6,
                    exposure=context.default_exposure,
                    severity=Severity.HIGH,
                    evidence=[evidence],
                    remediation=(
                        "Verify server-side authorization checks exist on this "
                        "endpoint and are enforced before returning content, "
                        "independent of any client-side/UI-only access "
                        "restriction."
                    ),
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
                    ],
                )
            )

        return findings
