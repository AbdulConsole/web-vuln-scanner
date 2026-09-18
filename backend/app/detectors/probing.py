"""
Shared parameter-testing helpers for detectors that probe individual
request parameters (SQL injection, reflected XSS).

Centralized so both detectors build probe requests identically -- notably,
stripping a URL's existing query string before re-attaching parameters
explicitly, so a probe value replaces the original rather than being
appended alongside it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from app.detectors.base import DetectionContext
from app.models.enums import HttpMethod
from app.scanner.request_engine import HttpResponse, RequestEngine


def strip_query(url: str) -> str:
    """Return url with its query string removed."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


@dataclass(frozen=True)
class ParamTarget:
    """One (url, method, parameter) combination worth probing, carrying the
    baseline values every *other* parameter on that request should keep so
    the request stays well-formed while only the target parameter varies.
    """

    url: str
    method: HttpMethod
    parameter_name: str
    baseline_values: dict[str, str] = field(default_factory=dict)

    async def send(self, engine: RequestEngine, override_value: str) -> HttpResponse:
        values = dict(self.baseline_values)
        values[self.parameter_name] = override_value
        if self.method == HttpMethod.GET:
            return await engine.get(self.url, params=values)
        return await engine.post(self.url, data=values)


def collect_param_targets(
    context: DetectionContext, *, max_targets: int = 200
) -> list[ParamTarget]:
    """Build testable parameter targets from the crawl's discovered query
    parameters and form fields, deduplicated by (url, method, parameter).

    Capped at max_targets: a large site can expose thousands of parameter
    combinations, and each costs several live requests per detector -- the
    cap keeps a scan's runtime bounded. Milestone 9's risk model doesn't
    depend on exhaustive parameter coverage, only on correctly scoring
    what was found.
    """
    seen: set[tuple[str, HttpMethod, str]] = set()
    targets: list[ParamTarget] = []

    for crawled in context.urls:
        base_url = strip_query(crawled.url)

        if crawled.parameters:
            baseline = {p.name: (p.sample_value or "1") for p in crawled.parameters}
            for param in crawled.parameters:
                key = (base_url, HttpMethod.GET, param.name)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    ParamTarget(
                        url=base_url,
                        method=HttpMethod.GET,
                        parameter_name=param.name,
                        baseline_values=baseline,
                    )
                )
                if len(targets) >= max_targets:
                    return targets

        for form in crawled.forms:
            if not form.inputs:
                continue
            # Never probe password fields: injecting test payloads into a
            # password field risks tripping account lockouts or other
            # auth-adjacent side effects, and it isn't a meaningful
            # injection surface for these checks anyway.
            testable_fields = [f for f in form.inputs if f.get("type") != "password"]
            if not testable_fields:
                continue
            baseline = {f["name"]: (f.get("value") or "1") for f in testable_fields}
            action_url = strip_query(form.action)

            for field_def in testable_fields:
                name = field_def["name"]
                key = (action_url, form.method, name)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    ParamTarget(
                        url=action_url,
                        method=form.method,
                        parameter_name=name,
                        baseline_values=baseline,
                    )
                )
                if len(targets) >= max_targets:
                    return targets

    return targets
