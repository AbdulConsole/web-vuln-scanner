from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.crawler.models import CrawledUrl, CrawlSummary, DiscoveredParameter
from app.detectors.sqli import SqlInjectionDetector
from app.models.enums import HttpMethod, ParameterSource

from ._detector_helpers import make_context, make_engine

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _summary_with_query_param(url: str, param_name: str = "id") -> CrawlSummary:
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


async def test_detects_confirmed_sqli_via_error_signature():
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params.get("id", "")
        if "'" in query:
            return httpx.Response(
                200, text="You have an error in your SQL syntax near '1''"
            )
        return httpx.Response(200, text="<html>normal page</html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_query_param("http://example.com/item?id=1"))

    async with engine:
        findings = await SqlInjectionDetector(engine).detect(context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vulnerability_type == "sql_injection"
    assert finding.confidence == 0.9
    assert finding.evidence[0].kind == "sql_error_signature"


async def test_detects_probable_sqli_via_boolean_differential():
    def handler(request: httpx.Request) -> httpx.Response:
        query = request.url.params.get("id", "")
        if "or '1'='1" in query.lower():
            return httpx.Response(200, text="<html>" + ("row " * 200) + "</html>")
        if "and '1'='2" in query.lower():
            return httpx.Response(200, text="<html>no results</html>")
        return httpx.Response(200, text="<html>baseline</html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_query_param("http://example.com/item?id=1"))

    async with engine:
        findings = await SqlInjectionDetector(engine).detect(context)

    assert len(findings) == 1
    assert findings[0].confidence == 0.5
    assert findings[0].evidence[0].kind == "boolean_differential"


async def test_no_finding_when_responses_are_identical():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>always the same</html>")

    engine = make_engine(handler)
    context = make_context(engine, _summary_with_query_param("http://example.com/item?id=1"))

    async with engine:
        findings = await SqlInjectionDetector(engine).detect(context)

    assert findings == []


async def test_no_finding_when_target_has_no_parameters():
    crawled = CrawledUrl(
        url="http://example.com/static",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
    )
    summary = CrawlSummary(target_base_url="http://example.com/", urls=[crawled])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>static</html>")

    engine = make_engine(handler)
    context = make_context(engine, summary)

    async with engine:
        findings = await SqlInjectionDetector(engine).detect(context)

    assert findings == []


async def test_respects_configured_max_targets():
    params = [
        DiscoveredParameter(name=f"p{i}", source=ParameterSource.QUERY, sample_value="1")
        for i in range(10)
    ]
    crawled = CrawledUrl(
        url="http://example.com/search",
        method=HttpMethod.GET,
        status_code=200,
        content_type="text/html",
        response_time_ms=10.0,
        depth=0,
        source_url=None,
        parameters=params,
    )
    summary = CrawlSummary(target_base_url="http://example.com/", urls=[crawled])

    request_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        request_count["n"] += 1
        return httpx.Response(200, text="<html>page</html>")

    engine = make_engine(handler)
    context = make_context(engine, summary)

    async with engine:
        detector = SqlInjectionDetector(engine, config={"max_targets": 2})
        await detector.detect(context)

    # 2 targets * up to 3 requests each (quote, true, false) = at most 6.
    assert request_count["n"] <= 6
