from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.detectors.security_headers import SecurityHeadersDetector

from ._detector_helpers import make_context, make_engine

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_flags_all_missing_headers_on_http():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>ok</html>")

    engine = make_engine(handler)
    context = make_context(engine)

    async with engine:
        findings = await SecurityHeadersDetector(engine).detect(context)

    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing X-Frame-Options header" in titles
    # HSTS shouldn't be recommended over plain HTTP.
    assert "Missing Strict-Transport-Security header" not in titles


async def test_hsts_is_checked_over_https():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    engine = make_engine(handler)
    context = make_context(engine)
    context.crawl_summary.target_base_url = "https://example.com/"

    async with engine:
        findings = await SecurityHeadersDetector(engine).detect(context)

    titles = {f.title for f in findings}
    assert "Missing Strict-Transport-Security header" in titles


async def test_no_findings_when_all_headers_present():
    good_headers = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", headers=good_headers)

    engine = make_engine(handler)
    context = make_context(engine)

    async with engine:
        findings = await SecurityHeadersDetector(engine).detect(context)

    assert findings == []


async def test_flags_weak_csp_directives():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="ok",
            headers={
                "content-security-policy": "default-src *; script-src 'unsafe-inline'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=()",
            },
        )

    engine = make_engine(handler)
    context = make_context(engine)

    async with engine:
        findings = await SecurityHeadersDetector(engine).detect(context)

    weak_csp_findings = [f for f in findings if f.title == "Weak Content-Security-Policy directives"]
    assert len(weak_csp_findings) == 1
    assert "unsafe-inline" in weak_csp_findings[0].evidence[0].payload["weak_directives_found"]


async def test_returns_no_findings_if_base_url_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("simulated", request=request)

    engine = make_engine(handler, max_retries=0)
    context = make_context(engine)

    async with engine:
        findings = await SecurityHeadersDetector(engine).detect(context)

    assert findings == []
