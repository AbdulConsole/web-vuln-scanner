"""
URL frontier (queue) management for the crawler.

Two distinct scope checks happen at two distinct points, deliberately:

1. Cheap domain-scope filtering happens here, at enqueue time, so the
   frontier never fills up with obviously out-of-scope external links
   (every page links off-site eventually).
2. Expensive network-safety validation (DNS resolution + blocklist check,
   via ScopeGuard.validate) happens once, right before the actual HTTP
   request is made, in Fetcher.fetch. That's the authoritative safety gate
   — this module's filtering is an optimization, not a security boundary
   on its own.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from app.core.url_utils import InvalidUrlError, normalize_url


@dataclass(frozen=True)
class FrontierItem:
    url: str
    depth: int
    source_url: str | None


class UrlManager:
    def __init__(
        self,
        *,
        max_depth: int,
        max_urls: int,
        is_in_scope: Callable[[str], bool],
    ):
        self.max_depth = max_depth
        self.max_urls = max_urls
        self._is_in_scope = is_in_scope
        self._seen: set[str] = set()
        self._queue: deque[FrontierItem] = deque()

    def seed(self, url: str) -> bool:
        """Add the initial URL to the frontier at depth 0, bypassing the
        scope filter (a target's own base_url is always in scope by
        definition — it's what defines the scope)."""
        try:
            normalized = normalize_url(url)
        except InvalidUrlError:
            return False
        if normalized in self._seen:
            return False
        self._seen.add(normalized)
        self._queue.append(FrontierItem(url=normalized, depth=0, source_url=None))
        return True

    def enqueue_discovered(self, raw_url: str, depth: int, source_url: str) -> bool:
        """Attempt to add a URL discovered during crawling. Returns True iff
        it was newly enqueued (useful for tests/metrics)."""
        if depth > self.max_depth:
            return False
        if len(self._seen) >= self.max_urls:
            return False
        try:
            normalized = normalize_url(raw_url)
        except InvalidUrlError:
            return False
        if normalized in self._seen:
            return False
        if not self._is_in_scope(normalized):
            return False

        self._seen.add(normalized)
        self._queue.append(
            FrontierItem(url=normalized, depth=depth, source_url=source_url)
        )
        return True

    def has_next(self) -> bool:
        return bool(self._queue)

    def pop_next(self) -> FrontierItem:
        return self._queue.popleft()

    def pop_batch(self, batch_size: int) -> list[FrontierItem]:
        batch: list[FrontierItem] = []
        while self._queue and len(batch) < batch_size:
            batch.append(self._queue.popleft())
        return batch

    @property
    def queue_length(self) -> int:
        return len(self._queue)

    @property
    def discovered_count(self) -> int:
        """Total distinct URLs ever seen (queued, popped, or still queued)."""
        return len(self._seen)
