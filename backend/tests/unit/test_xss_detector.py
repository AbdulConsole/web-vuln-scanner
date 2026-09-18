from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.crawler.models import CrawledUrl, CrawlSummary, DiscoveredForm, DiscoveredParameter
from app.detectors.xss import ReflectedXssDetector, StoredXssDetector, _classify_reflection
from app.models.enums import HttpMethod, ParameterSource

from ._detector_helpers import make_context, make_engine

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# --- classification helper -----------------------------------------------


def test_classify_confirmed_when_payload_reflected_verbatim():
    payload = "\"'><canary123"
    text = f"<div>{payload}</div>"
    assert _classify_reflection(text, "canary123", payload) == "confirmed"


def test_classify_none_when_not_reflected_at_all():
    assert _classify_reflection("<div>nothing here</div>", "canary123", "\"'><canary123") is None


def test_classify_none_when_properly_html_escaped():
    payload = "\"'><canary123"
    escaped = "&quot;&#x27;&gt;&lt;canary123"
    assert _classify_reflection(f"<div>{escaped}</div>", "canary123", payload) is None


def test_classify_probable_when_partially_neutralized():
    # Canary present, but neither the raw payload nor a clean HTML-escape
    # of it appears -- e.g. angle brackets stripped, quotes untouched.
    payload = "\"'><canary123"
    text = "<div>\"'canary123</div>"
    assert _classify_reflection(text, "canary123", payload) == "probable"


# --- reflected XSS ---------------------------------------------------------


def _summary_with_query_param(url: str, param_name: str = "q") -> CrawlSummary:
    crawled = CrawledUrl(
        url=url,
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
        parameters=[DiscoveredParameter(name=param_name, source=ParameterSource.QUERY, sample_value="1")],
    )
    return CrawlSummary(target_base_url="http://example.com/", urls=[crawled])


async def test_reflected_xss_confirmed_when_payload_echoed_unescaped():
    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        return httpx.Response(200, html=f"<html><body>Results for: {q}</body></html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_query_param("http://example.com/search?q=1"))

    async with engine:
        findings = await ReflectedXssDetector(engine).detect(context)

    assert len(findings) == 1
    assert findings[0].confidence == 0.85
    assert findings[0].severity.value == "high"


async def test_reflected_xss_no_finding_when_output_is_encoded():
    import html as html_mod

    def handler(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        return httpx.Response(200, html=f"<html><body>{html_mod.escape(q)}</body></html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_query_param("http://example.com/search?q=1"))

    async with engine:
        findings = await ReflectedXssDetector(engine).detect(context)

    assert findings == []


async def test_reflected_xss_no_finding_when_parameter_not_reflected():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>static content</body></html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_query_param("http://example.com/search?q=1"))

    async with engine:
        findings = await ReflectedXssDetector(engine).detect(context)

    assert findings == []


# --- stored XSS -------------------------------------------------------------


def _summary_with_comment_form(hosting_url: str) -> CrawlSummary:
    form = DiscoveredForm(
        action="http://example.com/comments/submit",
        method=HttpMethod.POST,
        inputs=[{"name": "comment", "type": "text", "value": ""}],
    )
    crawled = CrawledUrl(
        url=hosting_url,
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
        forms=[form],
    )
    return CrawlSummary(target_base_url="http://example.com/", urls=[crawled])


async def test_stored_xss_confirmed_when_canary_persists_unescaped():
    stored_value = {"comment": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/comments/submit":
            body = request.content.decode()
            stored_value["comment"] = httpx.QueryParams(body).get("comment", "")
            return httpx.Response(200, text="submitted")
        if request.url.path == "/comments":
            return httpx.Response(
                200, html=f"<html><body>{stored_value['comment']}</body></html>"
            )
        return httpx.Response(404)

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_comment_form("http://example.com/comments"))

    async with engine:
        findings = await StoredXssDetector(engine).detect(context)

    assert len(findings) == 1
    assert findings[0].vulnerability_type == "xss_stored"


async def test_stored_xss_skips_forms_with_password_fields():
    form = DiscoveredForm(
        action="http://example.com/login",
        method=HttpMethod.POST,
        inputs=[
            {"name": "username", "type": "text", "value": ""},
            {"name": "password", "type": "password", "value": ""},
        ],
    )
    crawled = CrawledUrl(
        url="http://example.com/login-page",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
        forms=[form],
    )
    summary = CrawlSummary(target_base_url="http://example.com/", urls=[crawled])

    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, text="ok")

    engine = make_engine(handler)
    context = make_context(engine, summary)

    async with engine:
        findings = await StoredXssDetector(engine).detect(context)

    assert findings == []
    assert called["n"] == 0  # never even attempted to submit a login form


async def test_stored_xss_no_finding_when_not_persisted():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/comments/submit":
            return httpx.Response(200, text="submitted")
        return httpx.Response(200, html="<html><body>no comments yet</body></html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_comment_form("http://example.com/comments"))

    async with engine:
        findings = await StoredXssDetector(engine).detect(context)

    assert findings == []
