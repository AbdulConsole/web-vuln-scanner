from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.crawler.models import CrawledUrl, CrawlSummary
from app.detectors.access_control import AccessControlDetector
from app.models.enums import HttpMethod

from ._detector_helpers import make_context, make_engine

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _summary_with_admin_url() -> CrawlSummary:
    crawled = CrawledUrl(
        url="http://example.com/admin/dashboard",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
    )
    return CrawlSummary(target_base_url="http://example.com/", urls=[crawled])


async def test_returns_no_findings_without_unauthenticated_engine():
    engine = make_engine(lambda r: httpx.Response(200, text="ok"))
    context = make_context(engine, _summary_with_admin_url())
    assert context.unauthenticated_engine is None

    async with engine:
        findings = await AccessControlDetector(engine).detect(context)

    assert findings == []


async def test_flags_admin_path_accessible_without_auth():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>Admin Dashboard</body></html>")

    auth_engine = make_engine(handler)
    unauth_engine = make_engine(handler)
    context = make_context(
        auth_engine, _summary_with_admin_url(), unauthenticated_engine=unauth_engine
    )

    async with auth_engine, unauth_engine:
        findings = await AccessControlDetector(auth_engine).detect(context)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "broken_access_control"


async def test_does_not_flag_when_unauthenticated_request_shows_login_page():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>Please log in</body></html>")

    unauth_engine = make_engine(handler)
    auth_engine = make_engine(handler)
    context = make_context(
        auth_engine, _summary_with_admin_url(), unauthenticated_engine=unauth_engine
    )

    async with auth_engine, unauth_engine:
        findings = await AccessControlDetector(auth_engine).detect(context)

    assert findings == []


async def test_does_not_flag_when_unauthenticated_request_is_redirected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://example.com/login"})

    # Note: the engine follows redirects by default; a 302 to a login page
    # off the sensitive path resolves to a non-sensitive final URL, so no
    # finding should be produced for the original admin URL either way.
    unauth_engine = make_engine(
        lambda r: httpx.Response(200, html="<html>Please log in</html>")
        if r.url.path == "/login"
        else httpx.Response(302, headers={"location": "http://example.com/login"})
    )
    auth_engine = make_engine(handler)
    context = make_context(
        auth_engine, _summary_with_admin_url(), unauthenticated_engine=unauth_engine
    )

    async with auth_engine, unauth_engine:
        findings = await AccessControlDetector(auth_engine).detect(context)

    assert findings == []


async def test_ignores_urls_without_sensitive_path_hints():
    crawled = CrawledUrl(
        url="http://example.com/blog/post-1",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
    )
    summary = CrawlSummary(target_base_url="http://example.com/", urls=[crawled])

    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, html="<html>blog post</html>")

    unauth_engine = make_engine(handler)
    auth_engine = make_engine(handler)
    context = make_context(auth_engine, summary, unauthenticated_engine=unauth_engine)

    async with auth_engine, unauth_engine:
        findings = await AccessControlDetector(auth_engine).detect(context)

    assert findings == []
    assert called["n"] == 0  # never even probed -- not a sensitive-looking path
