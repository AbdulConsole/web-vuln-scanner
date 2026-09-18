"""
Crawler domain models.

These are plain dataclasses, not the SQLAlchemy models in app/models —
deliberately so the crawler can be built, tested, and reasoned about with
zero database dependency. A later service (Milestone 11, when scans are
wired end-to-end) is responsible for translating these into Url/Form/
Parameter ORM rows. Reusing HttpMethod/ParameterSource from app.models.enums
here is a value-type reuse only (no ORM coupling), avoiding a duplicate
enum definition.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import HttpMethod, ParameterSource


@dataclass(frozen=True)
class DiscoveredParameter:
    name: str
    source: ParameterSource
    sample_value: str | None = None


@dataclass(frozen=True)
class DiscoveredForm:
    action: str
    method: HttpMethod
    inputs: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CrawledUrl:
    """One crawled page/resource and everything discovered on it."""

    url: str
    method: HttpMethod
    status_code: int | None
    content_type: str | None
    response_time_ms: float | None
    depth: int
    source_url: str | None
    forms: list[DiscoveredForm] = field(default_factory=list)
    parameters: list[DiscoveredParameter] = field(default_factory=list)
    # Populated for a failed or policy-blocked fetch (timeout, connection
    # error, out-of-scope redirect, robots.txt disallow). None means success.
    error: str | None = None


@dataclass
class CrawlSummary:
    """Aggregate result of one full crawl run, returned by Crawler.crawl()."""

    target_base_url: str
    urls: list[CrawledUrl] = field(default_factory=list)
    total_requests: int = 0
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False

    @property
    def discovered_forms(self) -> list[DiscoveredForm]:
        return [form for u in self.urls for form in u.forms]

    @property
    def discovered_parameters(self) -> list[DiscoveredParameter]:
        return [param for u in self.urls for param in u.parameters]
