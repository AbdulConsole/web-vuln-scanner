"""
Crawler orchestration (Section 7).

Runs a breadth-first crawl: fetches a batch of URLs from the frontier
concurrently (bounded by RequestEngine's semaphore), parses each response
for links/forms/parameters, enqueues newly discovered in-scope links, and
repeats until the frontier is empty, the URL cap is reached, or
cancellation is requested.

As of Milestone 5 the crawler owns no HTTP logic of its own: all requests
go through the shared RequestEngine, which is also what detectors use.
The crawler can either be handed an engine (the normal case, so a whole
scan shares one rate limiter, concurrency pool, and request counter) or
construct its own when run standalone.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from app.core.exceptions import ScopeViolationError
from app.core.logging import get_logger
from app.core.security import ScopeGuard
from app.crawler.models import CrawledUrl, CrawlSummary, DiscoveredParameter
from app.crawler.parser import (
    extract_form_parameters,
    extract_forms,
    extract_links,
    extract_query_parameters,
)
from app.crawler.robots import RobotsPolicy
from app.crawler.url_manager import FrontierItem, UrlManager
from app.models.enums import HttpMethod
from app.scanner.request_engine import RequestEngine, RequestSpec

logger = get_logger(__name__)


class Crawler:
    def __init__(
        self,
        *,
        scope_guard: ScopeGuard,
        base_url: str,
        scan_config: dict,
        request_engine: RequestEngine | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        """
        request_engine: a shared engine from the scan pipeline. When None,
            the crawler creates and owns one for the duration of the crawl
            (useful for standalone crawls and tests).
        transport: only used when constructing an internal engine; ignored
            if request_engine is supplied.
        """
        self.scope_guard = scope_guard
        self.base_url = base_url
        self._external_engine = request_engine
        self._transport = transport

        self.max_depth: int = scan_config.get("crawl_depth", 3)
        self.max_urls: int = scan_config.get("max_urls", 2000)
        self.timeout: float = scan_config.get("timeout", 10.0)
        self.rate_limit: float = scan_config.get("request_rate", 5.0)
        self.concurrency: int = scan_config.get("concurrency", 5)
        self.respect_robots_txt: bool = scan_config.get("respect_robots_txt", True)

        self.url_manager = UrlManager(
            max_depth=self.max_depth,
            max_urls=self.max_urls,
            is_in_scope=self._is_in_domain_scope,
        )
        self.robots_policy = RobotsPolicy(respect_robots_txt=self.respect_robots_txt)

    def _is_in_domain_scope(self, url: str) -> bool:
        """Cheap pre-filter used by UrlManager -- see url_manager.py's
        module docstring for why this is separate from the full
        ScopeGuard.validate() network-safety check done at request time."""
        try:
            self.scope_guard.check_domain_scope(url)
            return True
        except ScopeViolationError:
            return False

    @asynccontextmanager
    async def _engine(self) -> AsyncIterator[RequestEngine]:
        """Yield the shared engine if one was injected, otherwise create and
        clean up an internal one."""
        if self._external_engine is not None:
            yield self._external_engine
            return
        async with RequestEngine(
            self.scope_guard,
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            concurrency=self.concurrency,
            transport=self._transport,
        ) as engine:
            yield engine

    async def crawl(
        self, cancellation_token: asyncio.Event | None = None
    ) -> CrawlSummary:
        self.url_manager.seed(self.base_url)

        results: list[CrawledUrl] = []
        errors: list[str] = []
        requests_sent = 0
        cancelled = False

        async with self._engine() as engine:
            await self.robots_policy.load(self.base_url, engine.client)

            while self.url_manager.has_next():
                if cancellation_token is not None and cancellation_token.is_set():
                    cancelled = True
                    logger.info("Crawl cancelled by request")
                    break

                batch = self.url_manager.pop_batch(max(1, self.concurrency))
                batch_results = await asyncio.gather(
                    *(self._process_item(item, engine) for item in batch)
                )

                for crawled, discovered_links, made_request in batch_results:
                    results.append(crawled)
                    if made_request:
                        requests_sent += 1
                    if crawled.error:
                        errors.append(f"{crawled.url}: {crawled.error}")
                    for link in discovered_links:
                        self.url_manager.enqueue_discovered(
                            link, crawled.depth + 1, crawled.url
                        )

        logger.info(
            "Crawl finished",
            extra={
                "context": {
                    "base_url": self.base_url,
                    "urls_crawled": len(results),
                    "requests_sent": requests_sent,
                    "errors": len(errors),
                    "cancelled": cancelled,
                }
            },
        )

        return CrawlSummary(
            target_base_url=self.base_url,
            urls=results,
            total_requests=requests_sent,
            errors=errors,
            cancelled=cancelled,
        )

    async def _process_item(
        self, item: FrontierItem, engine: RequestEngine
    ) -> tuple[CrawledUrl, list[str], bool]:
        if not self.robots_policy.is_allowed(item.url, engine.user_agent):
            crawled = CrawledUrl(
                url=item.url,
                method=HttpMethod.GET,
                status_code=None,
                content_type=None,
                response_time_ms=None,
                depth=item.depth,
                source_url=item.source_url,
                error="blocked by robots.txt",
            )
            return crawled, [], False

        response = await engine.send(RequestSpec(url=item.url, method=HttpMethod.GET))

        discovered_links: list[str] = []
        parameters: list[DiscoveredParameter] = extract_query_parameters(item.url)
        forms = []

        if response.text and response.is_html:
            effective_base = response.final_url or item.url
            discovered_links = extract_links(response.text, effective_base)
            forms = extract_forms(response.text, effective_base)
            for form in forms:
                parameters.extend(extract_form_parameters(form))

        crawled = CrawledUrl(
            url=response.final_url or item.url,
            method=HttpMethod.GET,
            status_code=response.status_code,
            content_type=response.content_type,
            response_time_ms=response.elapsed_ms,
            depth=item.depth,
            source_url=item.source_url,
            forms=forms,
            parameters=parameters,
            error=response.error,
        )
        return crawled, discovered_links, True
