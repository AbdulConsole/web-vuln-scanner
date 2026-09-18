"""
Security Headers detector (Section 10.D).

Checks a single representative response (the target's base URL) rather
than every crawled page: these headers are almost always set at the
web-server/framework level and apply site-wide, so checking every page
would just produce the same finding hundreds of times over -- exactly the
duplicate-finding problem Section 17 warns about, for zero additional
information.
"""
from __future__ import annotations

from urllib.parse import urlparse

from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.detectors.manager import register_detector
from app.detectors.signatures import SECURITY_HEADERS
from app.models.enums import Severity
from app.scanner.request_engine import HttpResponse

_SEVERITY_MAP = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_WEAK_CSP_MARKERS = ["unsafe-inline", "unsafe-eval", "* ", "*;", "data:"]


@register_detector
class SecurityHeadersDetector(BaseDetector):
    name = "security_headers"
    vulnerability_type = "security_misconfiguration"
    description = (
        "Checks for the presence and quality of standard security-relevant "
        "HTTP response headers (CSP, X-Frame-Options, HSTS, etc.)."
    )
    default_severity = Severity.MEDIUM

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        base_url = context.crawl_summary.target_base_url
        response = await context.engine.get(base_url)
        if not response.ok:
            return []

        is_https = urlparse(base_url).scheme == "https"
        findings: list[DetectorFinding] = []

        for header_name, info in SECURITY_HEADERS.items():
            if header_name == "strict-transport-security" and not is_https:
                continue  # HSTS is meaningless to recommend over plain HTTP
            if header_name in response.headers:
                continue  # present -- no finding

            evidence = self.generate_evidence(
                "missing_header", {"header": header_name, "checked_url": base_url}
            )
            findings.append(
                self.make_finding(
                    url=base_url,
                    method=response.method,
                    title=info["title"],
                    description=info["description"],
                    confidence=1.0,  # header absence is directly observable
                    exploitability=0.3,
                    impact=0.4,
                    exposure=context.default_exposure,
                    severity=_SEVERITY_MAP[info["severity"]],
                    evidence=[evidence],
                    remediation=info["remediation"],
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )

        findings.extend(self._check_weak_csp(response, base_url, context))
        return findings

    def _check_weak_csp(
        self, response: HttpResponse, base_url: str, context: DetectionContext
    ) -> list[DetectorFinding]:
        csp = response.headers.get("content-security-policy")
        if not csp:
            return []

        matched = [marker for marker in _WEAK_CSP_MARKERS if marker in csp]
        if not matched:
            return []

        evidence = self.generate_evidence(
            "weak_csp", {"policy": csp, "weak_directives_found": matched}
        )
        return [
            self.make_finding(
                url=base_url,
                method=response.method,
                title="Weak Content-Security-Policy directives",
                description=(
                    f"The Content-Security-Policy header is present but "
                    f"contains directives that substantially weaken it: "
                    f"{', '.join(matched)}. These allow inline/eval'd script "
                    f"or overly broad sources, defeating much of CSP's "
                    f"protection against XSS."
                ),
                confidence=0.8,
                exploitability=0.4,
                impact=0.5,
                exposure=context.default_exposure,
                severity=Severity.LOW,
                evidence=[evidence],
                remediation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval' from script-src; "
                    "use nonces or hashes for necessary inline scripts, and "
                    "avoid wildcard source lists."
                ),
                references=["https://owasp.org/www-project-secure-headers/"],
            )
        ]
