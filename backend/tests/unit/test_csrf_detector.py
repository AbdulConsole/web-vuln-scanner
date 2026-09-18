from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.crawler.models import CrawledUrl, CrawlSummary, DiscoveredForm
from app.detectors.csrf import CsrfDetector
from app.models.enums import HttpMethod

from ._detector_helpers import make_context, make_engine

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _summary_with_form(form: DiscoveredForm) -> CrawlSummary:
    crawled = CrawledUrl(
        url="http://example.com/page",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
        forms=[form],
    )
    return CrawlSummary(target_base_url="http://example.com/", urls=[crawled])


def _handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200)


async def test_flags_post_form_without_csrf_token():
    form = DiscoveredForm(
        action="http://example.com/update-profile",
        method=HttpMethod.POST,
        inputs=[{"name": "email", "type": "text", "value": ""}],
    )
    engine = make_engine(_handler)
    context = make_context(engine, _summary_with_form(form))

    async with engine:
        findings = await CsrfDetector(engine).detect(context)

    assert len(findings) == 1
    assert findings[0].confidence == 0.35
    assert findings[0].severity.value == "medium"


async def test_does_not_flag_form_with_csrf_token_field():
    form = DiscoveredForm(
        action="http://example.com/update-profile",
        method=HttpMethod.POST,
        inputs=[
            {"name": "email", "type": "text", "value": ""},
            {"name": "csrf_token", "type": "hidden", "value": "abc123"},
        ],
    )
    engine = make_engine(_handler)
    context = make_context(engine, _summary_with_form(form))

    async with engine:
        findings = await CsrfDetector(engine).detect(context)

    assert findings == []


async def test_does_not_flag_get_forms():
    form = DiscoveredForm(
        action="http://example.com/search",
        method=HttpMethod.GET,
        inputs=[{"name": "q", "type": "text", "value": ""}],
    )
    engine = make_engine(_handler)
    context = make_context(engine, _summary_with_form(form))

    async with engine:
        findings = await CsrfDetector(engine).detect(context)

    assert findings == []


async def test_recognizes_various_token_field_names():
    for token_name in ["csrfmiddlewaretoken", "authenticity_token", "_token", "xsrf-token"]:
        form = DiscoveredForm(
            action="http://example.com/update",
            method=HttpMethod.POST,
            inputs=[
                {"name": "data", "type": "text", "value": ""},
                {"name": token_name, "type": "hidden", "value": "x"},
            ],
        )
        engine = make_engine(_handler)
        context = make_context(engine, _summary_with_form(form))

        async with engine:
            findings = await CsrfDetector(engine).detect(context)

        assert findings == [], f"token field '{token_name}' should have been recognized"


async def test_never_submits_requests_heuristic_only():
    """CSRF detection here must be purely static (no live HTTP calls) --
    it must never attempt to actually submit the form."""
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200)

    form = DiscoveredForm(
        action="http://example.com/update",
        method=HttpMethod.POST,
        inputs=[{"name": "data", "type": "text", "value": ""}],
    )
    engine = make_engine(handler)
    context = make_context(engine, _summary_with_form(form))

    async with engine:
        await CsrfDetector(engine).detect(context)

    assert call_count["n"] == 0
