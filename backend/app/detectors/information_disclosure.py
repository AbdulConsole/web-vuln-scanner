"""
Information Disclosure detector (Section 10.E).

Combines two safe techniques:

1. Active probing of a small, curated list of commonly-exposed sensitive
   paths (.git/config, .env, phpinfo.php, etc.) -- plain GET requests only.
2. Re-checking crawled URLs that returned a server error (5xx) for
   framework debug-page signatures (stack traces, "DEBUG = True", etc.).
   Limited to 5xx responses rather than every crawled page: debug pages
   overwhelmingly appear on error responses, and re-fetching every 200 OK
   page a second time just to scan for stack-trace text would roughly
   double the scan's request volume for very little additional detection
   value.
"""
from __future__ import annotations

from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.detectors.manager import register_detector
from app.detectors.probing import strip_query
from app.detectors.signatures import DEBUG_PAGE_SIGNATURES, SENSITIVE_PATH_SIGNATURES
from app.models.enums import HttpMethod, Severity


@register_detector
class InformationDisclosureDetector(BaseDetector):
    name = "information_disclosure"
    vulnerability_type = "information_disclosure"
    description = (
        "Probes for commonly-exposed sensitive files and checks error "
        "responses for framework debug output / stack traces."
    )
    default_severity = Severity.MEDIUM

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        findings.extend(await self._probe_sensitive_paths(context))
        findings.extend(await self._check_error_pages(context))
        return findings

    async def _probe_sensitive_paths(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        base_url = strip_query(context.crawl_summary.target_base_url).rstrip("/")

        for path, (signatures, title) in SENSITIVE_PATH_SIGNATURES.items():
            url = base_url + path
            response = await context.engine.get(url)
            if not response.ok or response.status_code != 200 or not response.text:
                continue

            matched = [s for s in signatures if s.lower() in response.text.lower()]
            if not matched:
                continue  # 200 status alone isn't enough evidence

            evidence = self.generate_evidence(
                "sensitive_file_exposed", {"url": url, "matched_signatures": matched}
            )
            findings.append(
                self.make_finding(
                    url=url,
                    method=HttpMethod.GET,
                    title=title,
                    description=(
                        f"'{path}' is accessible and its content matches known "
                        f"signatures for this file type, suggesting it is "
                        f"unintentionally exposed rather than a custom 200 "
                        f"response."
                    ),
                    confidence=0.85,
                    exploitability=0.6,
                    impact=0.7,
                    exposure=context.default_exposure,
                    severity=Severity.HIGH,
                    evidence=[evidence],
                    remediation=(
                        f"Remove or restrict web-server access to '{path}'. "
                        f"Ensure deployment processes don't copy VCS "
                        f"directories, environment files, or backups into the "
                        f"web root."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                )
            )

        return findings

    async def _check_error_pages(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        error_urls = [u for u in context.urls if u.status_code and u.status_code >= 500]

        for crawled in error_urls:
            response = await context.engine.get(crawled.url)
            if not response.ok or not response.text:
                continue

            lowered = response.text.lower()
            matched = [s for s in DEBUG_PAGE_SIGNATURES if s in lowered]
            if not matched:
                continue

            evidence = self.generate_evidence(
                "debug_page_signature", {"url": crawled.url, "matched_signatures": matched}
            )
            findings.append(
                self.make_finding(
                    url=crawled.url,
                    method=HttpMethod.GET,
                    title="Verbose error / debug information disclosed",
                    description=(
                        f"An error response at this URL contains debug output "
                        f"(matched: {', '.join(matched)}), which can reveal "
                        f"framework versions, file paths, or application "
                        f"internals useful to an attacker."
                    ),
                    confidence=0.8,
                    exploitability=0.4,
                    impact=0.5,
                    exposure=context.default_exposure,
                    severity=Severity.MEDIUM,
                    evidence=[evidence],
                    remediation=(
                        "Disable debug/development mode in production (e.g. "
                        "Django DEBUG=False, Flask debug=False) and return "
                        "generic error pages to end users while logging full "
                        "details server-side only."
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                )
            )

        return findings
