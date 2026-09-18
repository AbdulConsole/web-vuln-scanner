from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.crawler.models import CrawledUrl, CrawlSummary
from app.detectors.information_disclosure import InformationDisclosureDetector
from app.models.enums import HttpMethod

from ._detector_helpers import make_context, make_engine

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def test_detects_exposed_git_config():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.git/config":
            return httpx.Response(
                200, text="[core]\n\trepositoryformatversion = 0\n"
            )
        return httpx.Response(404)

    engine = make_engine(handler)
    context = make_context(engine)

    async with engine:
        findings = await InformationDisclosureDetector(engine).detect(context)

    matching = [f for f in findings if ".git" in f.url]
    assert len(matching) == 1
    assert matching[0].confidence == 0.85


async def test_does_not_flag_200_without_content_signature():
    """A site with a catch-all 200 'not found' page must not be flagged
    just because every path returns 200."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>Sorry, page not found</html>")

    engine = make_engine(handler)
    context = make_context(engine)

    async with engine:
        findings = await InformationDisclosureDetector(engine).detect(context)

    assert findings == []


async def test_detects_debug_page_on_error_response():
    crawled = CrawledUrl(
        url="http://example.com/broken",
        method=HttpMethod.GET,
        status_code=500,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
    )
    summary = CrawlSummary(target_base_url="http://example.com/", urls=[crawled])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/broken":
            return httpx.Response(
                500, text="Traceback (most recent call last):\n  File 'app.py'"
            )
        return httpx.Response(404)

    engine = make_engine(handler)
    context = make_context(engine, summary)

    async with engine:
        findings = await InformationDisclosureDetector(engine).detect(context)

    matching = [f for f in findings if f.url == "http://example.com/broken"]
    assert len(matching) == 1
    assert matching[0].title == "Verbose error / debug information disclosed"


async def test_does_not_recheck_successful_pages_for_debug_signatures():
    """Only 5xx crawled URLs are re-checked for debug signatures -- a 200
    page is not re-fetched for this check (documented perf tradeoff)."""
    crawled = CrawledUrl(
        url="http://example.com/fine",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
    )
    summary = CrawlSummary(target_base_url="http://example.com/", urls=[crawled])

    fetch_log = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetch_log.append(request.url.path)
        if request.url.path == "/fine":
            # Even though this page happens to contain a debug-like string,
            # it must not be re-checked because its crawled status was 200.
            return httpx.Response(200, text="stack trace: oops")
        return httpx.Response(404)

    engine = make_engine(handler)
    context = make_context(engine, summary)

    async with engine:
        findings = await InformationDisclosureDetector(engine).detect(context)

    assert "/fine" not in fetch_log
    assert findings == []
