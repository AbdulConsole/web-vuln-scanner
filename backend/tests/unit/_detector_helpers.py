"""
Shared construction helpers for detector unit tests. Named with a leading
underscore so pytest does not try to collect this as a test module itself.
"""
from __future__ import annotations

from typing import Optional

import httpx

from app.core.security import ScopeGuard, ScopePolicy
from app.crawler.models import CrawlSummary
from app.detectors.base import DetectionContext
from app.scanner.request_engine import RequestEngine


def make_engine(handler, **kwargs) -> RequestEngine:
    guard = ScopeGuard(ScopePolicy(base_domain="example.com"))
    defaults = dict(timeout=5, rate_limit=0, concurrency=5)
    defaults.update(kwargs)
    return RequestEngine(guard, transport=httpx.MockTransport(handler), **defaults)


def make_context(
    engine: RequestEngine,
    crawl_summary: Optional[CrawlSummary] = None,
    **kwargs,
) -> DetectionContext:
    return DetectionContext(
        engine=engine,
        crawl_summary=crawl_summary or CrawlSummary(target_base_url="http://example.com/"),
        **kwargs,
    )
