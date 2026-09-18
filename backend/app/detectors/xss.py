"""
Cross-Site Scripting detectors: reflected (Section 10.B) and stored
(Section 10.C). Both use a non-executing canary string -- no JavaScript is
ever run; detection is purely static string/encoding analysis of the
response body, so this can never accidentally trigger a real XSS payload
against the target.
"""
from __future__ import annotations

import html
import secrets
from typing import Any

from app.detectors.base import BaseDetector, DetectionContext, DetectorFinding
from app.detectors.manager import register_detector
from app.detectors.probing import ParamTarget, collect_param_targets, strip_query
from app.models.enums import HttpMethod, Severity


def _build_canary() -> str:
    return f"vsxss{secrets.token_hex(4)}"


def _build_payload(canary: str) -> str:
    return f"\"'><{canary}"


def _classify_reflection(response_text: str, canary: str, raw_payload: str) -> str | None:
    """Return 'confirmed', 'probable', or None (not reflected, or reflected
    but safely encoded)."""
    if raw_payload in response_text:
        return "confirmed"
    if canary not in response_text:
        return None
    escaped = html.escape(raw_payload)
    if escaped in response_text:
        return None  # properly HTML-encoded: not exploitable via this vector
    # Canary survived but the exact payload didn't, and it wasn't cleanly
    # escaped either (e.g. quotes survived but angle brackets were
    # stripped). Can't confirm an executable context, but can't call it
    # safe either.
    return "probable"


@register_detector
class ReflectedXssDetector(BaseDetector):
    name = "xss_reflected"
    vulnerability_type = "xss_reflected"
    description = (
        "Tests request parameters for reflected XSS by checking whether a "
        "unique, non-executing canary payload is reflected unescaped in "
        "the response."
    )
    default_severity = Severity.HIGH

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        max_targets = self.config.get("max_targets", 150)
        targets = collect_param_targets(context, max_targets=max_targets)

        for target in targets:
            finding = await self._test_target(target, context)
            if finding is not None:
                findings.append(finding)

        return findings

    async def _test_target(
        self, target: ParamTarget, context: DetectionContext
    ) -> DetectorFinding | None:
        canary = _build_canary()
        payload = _build_payload(canary)

        response = await target.send(context.engine, payload)
        if not response.ok or not response.text:
            return None

        classification = _classify_reflection(response.text, canary, payload)
        if classification is None:
            return None

        confirmed = classification == "confirmed"
        evidence = self.generate_evidence(
            "reflection",
            {
                "parameter": target.parameter_name,
                "payload": payload,
                "classification": classification,
            },
        )
        return self.make_finding(
            url=target.url,
            method=target.method,
            parameter=target.parameter_name,
            title=f"Reflected XSS in parameter '{target.parameter_name}'",
            description=(
                f"A test payload injected into '{target.parameter_name}' was "
                f"reflected in the response "
                + (
                    "completely unescaped, meaning it would execute as "
                    "HTML/script in a browser."
                    if confirmed
                    else "with some special characters surviving encoding or "
                    "filtering; manual verification is recommended to "
                    "confirm exploitability in this specific context."
                )
            ),
            confidence=0.85 if confirmed else 0.4,
            exploitability=0.7 if confirmed else 0.35,
            impact=0.6,
            exposure=context.default_exposure,
            severity=Severity.HIGH if confirmed else Severity.MEDIUM,
            evidence=[evidence],
            remediation=(
                "Apply context-appropriate output encoding (HTML-entity "
                "encode for HTML body context, attribute-encode for "
                "attribute context, JS-string-encode for script context). "
                "Prefer a templating engine with automatic escaping over "
                "manual string concatenation."
            ),
            references=["https://owasp.org/www-community/attacks/xss/"],
        )


@register_detector
class StoredXssDetector(BaseDetector):
    name = "xss_stored"
    vulnerability_type = "xss_stored"
    description = (
        "Submits a unique, non-executing canary to POST forms and checks "
        "whether it is later rendered back on the hosting page, indicating "
        "the input is stored and displayed without sanitization."
    )
    default_severity = Severity.HIGH

    async def detect(self, context: DetectionContext) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for crawled in context.urls:
            for form in crawled.forms:
                if form.method != HttpMethod.POST:
                    continue
                if any(f.get("type") == "password" for f in form.inputs):
                    # Skip anything that looks like an auth form: not a
                    # meaningful stored-XSS surface, and submitting to it
                    # risks auth-adjacent side effects (Section 1 safety).
                    continue
                if not form.inputs:
                    continue

                finding = await self._test_form(crawled.url, form, context)
                if finding is not None:
                    findings.append(finding)

        return findings

    async def _test_form(
        self, hosting_url: str, form: Any, context: DetectionContext
    ) -> DetectorFinding | None:
        canary = _build_canary()
        payload = _build_payload(canary)

        values = {
            f["name"]: (f.get("value") or "1")
            for f in form.inputs
            if f.get("type") != "password"
        }
        if not values:
            return None
        # Inject the canary into every text-like field rather than
        # guessing which one is "the" content field. Harmless to apply
        # broadly since the canary is inert.
        for name in values:
            values[name] = payload

        submit_response = await context.engine.post(strip_query(form.action), data=values)
        if not submit_response.ok:
            return None

        # Re-fetch the page that hosted the form to check for persistence.
        # KNOWN LIMITATION: this only checks the hosting page, not other
        # pages the stored value might also render on (e.g. a separate
        # "view all comments" page) -- see docs/architecture.md.
        verify_response = await context.engine.get(hosting_url)
        if not verify_response.ok or not verify_response.text:
            return None

        classification = _classify_reflection(verify_response.text, canary, payload)
        if classification is None:
            return None

        confirmed = classification == "confirmed"
        evidence = self.generate_evidence(
            "stored_reflection",
            {
                "form_action": form.action,
                "hosting_url": hosting_url,
                "payload": payload,
                "classification": classification,
            },
        )
        return self.make_finding(
            url=form.action,
            method=HttpMethod.POST,
            title="Stored XSS via form submission",
            description=(
                f"A test payload submitted to the form at '{form.action}' was "
                f"found rendered back, unescaped, on '{hosting_url}' after "
                f"submission -- indicating stored input is rendered without "
                f"sanitization."
                if confirmed
                else f"A test payload submitted to '{form.action}' appears to "
                f"persist and partially survive encoding on '{hosting_url}'; "
                f"manual verification recommended."
            ),
            confidence=0.75 if confirmed else 0.35,
            exploitability=0.6 if confirmed else 0.3,
            impact=0.75,
            exposure=context.default_exposure,
            severity=Severity.HIGH if confirmed else Severity.MEDIUM,
            evidence=[evidence],
            remediation=(
                "Sanitize and/or output-encode all user-submitted content at "
                "render time, not just at submission time. Consider a "
                "strict allow-list-based HTML sanitizer if some markup must "
                "be preserved (e.g. rich text)."
            ),
            references=["https://owasp.org/www-community/attacks/xss/"],
        )
