from __future__ import annotations

import asyncio

import httpx
import pytest

from app.core.config import get_settings
from app.core.security import ScopeGuard, ScopePolicy
from app.crawler.crawler import Crawler
from app.models.enums import HttpMethod

pytestmark = pytest.mark.asyncio

_PAGES = {
    "/": """
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
        <form action="/search" method="get"><input name="q"></form>
    """,
    "/about": """
        <a href="/">Home</a>
        <a href="/deep1">Deep 1</a>
    """,
    "/contact": """
        <form action="/submit" method="post">
            <input name="name">
            <input name="email">
        </form>
    """,
    "/deep1": '<a href="/deep2">Deep 2</a>',
    "/deep2": "<p>too deep to matter</p>",
}


def _handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/robots.txt":
        return httpx.Response(404)
    if path in _PAGES:
        return httpx.Response(200, html=_PAGES[path])
    return httpx.Response(404)


@pytest.fixture(autouse=True)
def _reset_settings(monkeypatch):
    # These tests exercise crawl orchestration (BFS, dedup, depth limits,
    # forms/params, robots.txt, cancellation) via a MockTransport -- they
    # are not meant to depend on real DNS. ScopeGuard's network-safety
    # check does a real socket.getaddrinfo() unless this is set, which
    # would make these tests network-dependent and fragile. Domain-scope
    # checks (which ARE exercised here) don't require DNS and are
    # unaffected by this flag.
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _make_crawler(**config_overrides) -> Crawler:
    guard = ScopeGuard(ScopePolicy(base_domain="example.com"))
    scan_config = {
        "crawl_depth": 2,
        "max_urls": 100,
        "timeout": 5,
        "request_rate": 1000,
        "concurrency": 5,
        "respect_robots_txt": True,
        **config_overrides,
    }
    return Crawler(
        scope_guard=guard,
        base_url="http://example.com/",
        scan_config=scan_config,
        transport=httpx.MockTransport(_handler),
    )


async def test_crawl_discovers_pages_within_depth_limit():
    crawler = _make_crawler(crawl_depth=2)
    summary = await crawler.crawl()

    crawled_paths = {httpx.URL(u.url).path for u in summary.urls}
    assert "/" in crawled_paths
    assert "/about" in crawled_paths
    assert "/contact" in crawled_paths
    assert "/deep1" in crawled_paths  # depth 2, within limit
    assert "/deep2" not in crawled_paths  # depth 3, exceeds max_depth=2

    assert summary.cancelled is False
    assert len(summary.errors) == 0


async def test_crawl_deduplicates_the_link_back_to_home():
    crawler = _make_crawler(crawl_depth=2)
    summary = await crawler.crawl()

    home_visits = [u for u in summary.urls if httpx.URL(u.url).path == "/"]
    assert len(home_visits) == 1  # /about links back to / but it's already seen


async def test_crawl_discovers_forms_and_parameters():
    crawler = _make_crawler(crawl_depth=2)
    summary = await crawler.crawl()

    forms = summary.discovered_forms
    actions = {httpx.URL(f.action).path for f in forms}
    assert "/search" in actions
    assert "/submit" in actions

    submit_form = next(f for f in forms if httpx.URL(f.action).path == "/submit")
    assert submit_form.method == HttpMethod.POST
    field_names = {i["name"] for i in submit_form.inputs}
    assert field_names == {"name", "email"}

    param_names = {p.name for p in summary.discovered_parameters}
    assert "q" in param_names


async def test_crawl_respects_max_urls_cap():
    crawler = _make_crawler(crawl_depth=10, max_urls=2)
    summary = await crawler.crawl()

    # The frontier caps total *discovered* URLs at 2 (seed + one more); the
    # seed itself is always crawled regardless of the cap.
    assert len(summary.urls) <= 2


async def test_crawl_can_be_cancelled_gracefully():
    crawler = _make_crawler(crawl_depth=10, concurrency=1)
    cancellation_token = asyncio.Event()
    cancellation_token.set()  # cancel before the loop even starts

    summary = await crawler.crawl(cancellation_token=cancellation_token)

    assert summary.cancelled is True
    # Nothing should have been crawled since we cancelled immediately.
    assert summary.total_requests == 0


async def test_crawl_tracks_request_count_separately_from_robots_blocked_urls():
    def handler_with_admin_disallow(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /admin")
        if request.url.path == "/":
            return httpx.Response(200, html='<a href="/admin">Admin</a><a href="/about">About</a>')
        if request.url.path == "/about":
            return httpx.Response(200, html="")
        return httpx.Response(404)

    guard = ScopeGuard(ScopePolicy(base_domain="example.com"))
    crawler = Crawler(
        scope_guard=guard,
        base_url="http://example.com/",
        scan_config={
            "crawl_depth": 2,
            "max_urls": 100,
            "timeout": 5,
            "request_rate": 1000,
            "concurrency": 5,
            "respect_robots_txt": True,
        },
        transport=httpx.MockTransport(handler_with_admin_disallow),
    )
    summary = await crawler.crawl()

    admin_entry = next(u for u in summary.urls if httpx.URL(u.url).path == "/admin")
    assert admin_entry.error == "blocked by robots.txt"
    # / and /about were real requests; /admin was policy-blocked, not a request.
    assert summary.total_requests == 2


async def test_crawler_uses_injected_shared_request_engine():
    """The whole point of Milestone 5: when a scan supplies one engine, the
    crawler must use it rather than creating its own, so rate limiting,
    concurrency, and request metrics are shared across the entire scan
    instead of being per-component."""
    from app.scanner.request_engine import RequestEngine

    guard = ScopeGuard(ScopePolicy(base_domain="example.com"))
    scan_config = {
        "crawl_depth": 1,
        "max_urls": 100,
        "timeout": 5,
        "request_rate": 0,
        "concurrency": 5,
        "respect_robots_txt": False,
    }

    async with RequestEngine(
        guard,
        timeout=5,
        rate_limit=0,
        concurrency=5,
        transport=httpx.MockTransport(_handler),
    ) as shared_engine:
        # A request made before the crawl, as a detector might.
        await shared_engine.get("http://example.com/about")
        baseline = shared_engine.metrics.requests_sent

        crawler = Crawler(
            scope_guard=guard,
            base_url="http://example.com/",
            scan_config=scan_config,
            request_engine=shared_engine,
        )
        summary = await crawler.crawl()

        # The crawler's requests landed on the same counter as the
        # pre-crawl request, proving no second engine was created.
        assert shared_engine.metrics.requests_sent > baseline
        assert shared_engine.metrics.requests_sent >= summary.total_requests + baseline
