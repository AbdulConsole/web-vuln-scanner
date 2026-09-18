"""
Centralized request engine (Section 8).

Every outbound HTTP request the scanner makes -- crawler page fetches,
detector probes, verification requests -- goes through this class. Nothing
else in the codebase should construct an httpx client. This matters for
three reasons:

1. Security: scope + SSRF validation happens here, on every request and on
   every redirect hop, so no detector can accidentally bypass it.
2. Politeness: rate limiting and concurrency bounds are enforced globally
   for a scan, not per-component. Five detectors each doing their own
   "5 req/s" would mean 25 req/s hitting the target.
3. Metrics: a single request counter backs the scan-progress reporting
   required by Section 18.

This replaces app/crawler/fetcher.py from Milestone 4, which carried a
duplicate HTTP implementation while this module did not yet exist. That
consolidation debt is now paid: the crawler delegates here.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from app.core.exceptions import ScopeViolationError, UnsafeTargetError
from app.core.logging import get_logger
from app.core.security import ScopeGuard
from app.models.enums import HttpMethod
from app.scanner.rate_limiter import RateLimiter

logger = get_logger(__name__)

DEFAULT_USER_AGENT = "VulnScanner/0.1 (+authorized-security-testing)"

# Only bodies of these content types are decoded to text. Everything else
# (images, archives, binaries) is left undecoded -- detectors operate on
# text, and decoding a 50MB binary wastes memory for no benefit.
_TEXTUAL_CONTENT_HINTS = ("html", "text", "json", "xml", "javascript")


@dataclass(frozen=True)
class RequestSpec:
    """A single HTTP request to perform.

    Detectors build these declaratively rather than calling an HTTP client,
    which is what keeps detector code free of transport concerns.
    """

    url: str
    method: HttpMethod = HttpMethod.GET
    params: Mapping[str, Any] | None = None
    data: Mapping[str, Any] | None = None
    json_body: Any | None = None
    headers: Mapping[str, str] | None = None
    cookies: Mapping[str, str] | None = None
    follow_redirects: bool = True
    max_redirects: int = 5


@dataclass
class HttpResponse:
    """Captured response plus the metadata detectors and evidence
    collection need."""

    request_url: str
    final_url: str | None
    method: HttpMethod
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str | None = None
    text: str | None = None
    body_bytes: int | None = None
    elapsed_ms: float | None = None
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None

    @property
    def is_html(self) -> bool:
        return bool(self.content_type and "html" in self.content_type.lower())


@dataclass
class RequestMetrics:
    requests_sent: int = 0
    requests_failed: int = 0
    blocked_by_scope: int = 0
    total_bytes: int = 0


class RequestEngine:
    """Async context manager owning the scan's single HTTP client.

    Usage:
        async with RequestEngine(scope_guard, timeout=10, rate_limit=5,
                                 concurrency=5) as engine:
            response = await engine.send(RequestSpec(url="https://example.com/"))
    """

    def __init__(
        self,
        scope_guard: ScopeGuard,
        *,
        timeout: float,
        rate_limit: float,
        concurrency: int,
        max_response_bytes: int = 2_000_000,
        max_retries: int = 2,
        user_agent: str = DEFAULT_USER_AGENT,
        default_headers: Mapping[str, str] | None = None,
        default_cookies: Mapping[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._scope_guard = scope_guard
        self._timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self._rate_limiter = RateLimiter(rate_limit)
        self._max_response_bytes = max_response_bytes
        self._max_retries = max_retries
        self._user_agent = user_agent
        self._default_cookies = dict(default_cookies or {})
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self.metrics = RequestMetrics()

        self._default_headers = {"User-Agent": user_agent}
        if default_headers:
            self._default_headers.update(default_headers)

    # -- lifecycle -------------------------------------------------------

    async def __aenter__(self) -> RequestEngine:
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            # Redirects are followed manually so scope can be re-validated
            # on each hop -- see _send_once.
            follow_redirects=False,
            headers=self._default_headers,
            cookies=self._default_cookies,
            transport=self._transport,
        )
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(
                "RequestEngine must be used as an async context manager "
                "(async with RequestEngine(...) as engine:)"
            )
        return self._client

    @property
    def user_agent(self) -> str:
        return self._user_agent

    # -- public API -------------------------------------------------------

    async def send(self, spec: RequestSpec) -> HttpResponse:
        """Perform a request, following in-scope redirects. Never raises for
        network/scope failures -- those are returned on the HttpResponse's
        `error` field, so a single bad URL can't abort a whole scan."""
        current_url = spec.url
        redirect_chain: list[str] = []

        for hop in range(spec.max_redirects + 1):
            try:
                self._scope_guard.validate(current_url)
            except (ScopeViolationError, UnsafeTargetError) as exc:
                self.metrics.blocked_by_scope += 1
                return HttpResponse(
                    request_url=spec.url,
                    final_url=None,
                    method=spec.method,
                    status_code=None,
                    redirect_chain=redirect_chain,
                    error=f"blocked by scope guard: {exc}",
                )

            # Body/params are sent on the original request only; a redirect
            # hop is re-issued as a bodyless GET where the status demands it
            # (303, and 301/302 in practice), matching browser behaviour.
            is_redirect_hop = hop > 0
            response, elapsed_ms, error = await self._send_once(
                current_url, spec, as_plain_get=is_redirect_hop
            )

            if error is not None:
                self.metrics.requests_failed += 1
                return HttpResponse(
                    request_url=spec.url,
                    final_url=None,
                    method=spec.method,
                    status_code=None,
                    redirect_chain=redirect_chain,
                    error=error,
                )

            assert response is not None  # guaranteed: error was None

            if response.is_redirect and spec.follow_redirects:
                location = response.headers.get("location")
                if not location:
                    return self._build_response(
                        spec, current_url, response, elapsed_ms, redirect_chain,
                        error="redirect response missing Location header",
                    )
                if hop == spec.max_redirects:
                    return self._build_response(
                        spec, current_url, response, elapsed_ms, redirect_chain,
                        error=f"too many redirects (> {spec.max_redirects})",
                    )
                current_url = urljoin(current_url, location)
                redirect_chain.append(current_url)
                continue  # re-validates scope at the top of the loop

            return self._build_response(
                spec, current_url, response, elapsed_ms, redirect_chain
            )

        return HttpResponse(
            request_url=spec.url,
            final_url=None,
            method=spec.method,
            status_code=None,
            redirect_chain=redirect_chain,
            error="unexpected: redirect loop exited without a result",
        )

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.send(RequestSpec(url=url, method=HttpMethod.GET, **kwargs))

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.send(RequestSpec(url=url, method=HttpMethod.POST, **kwargs))

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        return await self.send(RequestSpec(url=url, method=HttpMethod.HEAD, **kwargs))

    # -- internals ---------------------------------------------------------

    async def _send_once(
        self, url: str, spec: RequestSpec, *, as_plain_get: bool
    ) -> tuple[httpx.Response | None, float | None, str | None]:
        """Issue one HTTP request with bounded retries on transient errors."""
        async with self._semaphore:
            for attempt in range(self._max_retries + 1):
                await self._rate_limiter.acquire()
                start = time.monotonic()
                try:
                    if as_plain_get:
                        response = await self.client.request(
                            HttpMethod.GET.value,
                            url,
                            headers=dict(spec.headers) if spec.headers else None,
                            cookies=dict(spec.cookies) if spec.cookies else None,
                        )
                    else:
                        response = await self.client.request(
                            spec.method.value,
                            url,
                            params=dict(spec.params) if spec.params else None,
                            data=dict(spec.data) if spec.data else None,
                            json=spec.json_body,
                            headers=dict(spec.headers) if spec.headers else None,
                            cookies=dict(spec.cookies) if spec.cookies else None,
                        )
                    elapsed_ms = (time.monotonic() - start) * 1000
                    self.metrics.requests_sent += 1
                    return response, elapsed_ms, None

                except httpx.TimeoutException as exc:
                    if attempt < self._max_retries:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    return None, None, (
                        f"timeout after {self._max_retries + 1} attempts: {exc}"
                    )
                except httpx.HTTPError as exc:
                    if attempt < self._max_retries:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    return None, None, (
                        f"request failed after {self._max_retries + 1} attempts: {exc}"
                    )

        return None, None, "unexpected: retry loop exited without a result"

    def _build_response(
        self,
        spec: RequestSpec,
        final_url: str,
        response: httpx.Response,
        elapsed_ms: float | None,
        redirect_chain: list[str],
        error: str | None = None,
    ) -> HttpResponse:
        content_type = response.headers.get("content-type")
        raw = response.content
        self.metrics.total_bytes += len(raw)

        truncated = len(raw) > self._max_response_bytes
        text = self._decode_text(response, raw, content_type)

        return HttpResponse(
            request_url=spec.url,
            final_url=final_url,
            method=spec.method,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            content_type=content_type,
            text=text,
            body_bytes=len(raw),
            elapsed_ms=elapsed_ms,
            redirect_chain=redirect_chain,
            error=error,
            truncated=truncated,
        )

    def _decode_text(
        self, response: httpx.Response, raw: bytes, content_type: str | None
    ) -> str | None:
        if not content_type:
            return None
        lowered = content_type.lower()
        if not any(hint in lowered for hint in _TEXTUAL_CONTENT_HINTS):
            return None

        # KNOWN LIMITATION (carried over from Milestone 4, unchanged): httpx
        # has already buffered the full body by this point, so this bounds
        # what we *retain*, not what we *download*. A true download cap
        # requires streaming responses; that's a planned hardening item.
        clipped = raw[: self._max_response_bytes]
        encoding = response.encoding or "utf-8"
        try:
            return clipped.decode(encoding, errors="replace")
        except (LookupError, TypeError):
            return clipped.decode("utf-8", errors="replace")
