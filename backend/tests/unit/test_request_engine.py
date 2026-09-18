from __future__ import annotations

import httpx
import pytest

from app.core.config import get_settings
from app.core.security import ScopeGuard, ScopePolicy
from app.models.enums import HttpMethod
from app.scanner.request_engine import RequestEngine, RequestSpec

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _lab_mode(monkeypatch):
    # These tests exercise the engine's own logic (redirects, retries,
    # metrics, body handling). SSRF/DNS behaviour is covered separately in
    # test_security_scope_guard.py; MockTransport intercepts the HTTP layer
    # but not socket.getaddrinfo, so real DNS is disabled here to keep
    # these tests fast and network-independent. Domain-scope checks still
    # run and are asserted below.
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _guard(base_domain: str = "example.com") -> ScopeGuard:
    return ScopeGuard(ScopePolicy(base_domain=base_domain))


def _engine(handler, **kwargs) -> RequestEngine:
    defaults = dict(timeout=5, rate_limit=0, concurrency=5)
    defaults.update(kwargs)
    return RequestEngine(
        _guard(), transport=httpx.MockTransport(handler), **defaults
    )


async def test_get_returns_status_headers_and_text():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><body>hello</body></html>")

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/")

    assert response.ok is True
    assert response.status_code == 200
    assert "hello" in (response.text or "")
    assert response.is_html is True
    assert response.final_url == "http://example.com/"
    assert response.elapsed_ms is not None


async def test_post_sends_form_data():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["body"] = request.content.decode()
        return httpx.Response(200, text="ok")

    async with _engine(handler) as engine:
        await engine.post("http://example.com/login", data={"user": "alice"})

    assert captured["method"] == "POST"
    assert "user=alice" in captured["body"]


async def test_query_params_are_sent():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["query"] = str(request.url.query.decode())
        return httpx.Response(200, text="ok")

    async with _engine(handler) as engine:
        await engine.get("http://example.com/search", params={"q": "test"})

    assert "q=test" in captured["query"]


async def test_custom_headers_and_cookies_are_sent():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["x_test"] = request.headers.get("x-test")
        captured["cookie"] = request.headers.get("cookie")
        return httpx.Response(200, text="ok")

    async with _engine(handler) as engine:
        await engine.send(
            RequestSpec(
                url="http://example.com/",
                headers={"X-Test": "abc"},
                cookies={"session": "xyz"},
            )
        )

    assert captured["x_test"] == "abc"
    assert "session=xyz" in (captured["cookie"] or "")


async def test_default_user_agent_is_applied():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["ua"] = request.headers.get("user-agent")
        return httpx.Response(200, text="ok")

    async with _engine(handler) as engine:
        await engine.get("http://example.com/")

    assert "VulnScanner" in captured["ua"]


async def test_head_request_uses_head_method():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(200)

    async with _engine(handler) as engine:
        await engine.head("http://example.com/")

    assert captured["method"] == "HEAD"


async def test_follows_in_scope_redirect_and_records_chain():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/old":
            return httpx.Response(302, headers={"location": "http://example.com/new"})
        return httpx.Response(200, html="<html>new</html>")

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/old")

    assert response.status_code == 200
    assert response.final_url == "http://example.com/new"
    assert response.redirect_chain == ["http://example.com/new"]


async def test_rejects_redirect_to_out_of_scope_domain():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://evil.com/steal"})

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/")

    assert response.ok is False
    assert "scope guard" in (response.error or "")
    assert engine.metrics.blocked_by_scope == 1


async def test_rejects_initial_out_of_scope_url_without_sending_request():
    sent = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        sent["count"] += 1
        return httpx.Response(200)

    async with _engine(handler) as engine:
        response = await engine.get("http://evil.com/")

    assert response.ok is False
    assert sent["count"] == 0  # blocked before any network call
    assert engine.metrics.requests_sent == 0


async def test_can_disable_redirect_following():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://example.com/new"})

    async with _engine(handler) as engine:
        response = await engine.send(
            RequestSpec(url="http://example.com/old", follow_redirects=False)
        )

    assert response.status_code == 302
    assert response.redirect_chain == []


async def test_reports_too_many_redirects():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        return httpx.Response(
            302, headers={"location": f"http://example.com/hop{counter['n']}"}
        )

    async with _engine(handler) as engine:
        response = await engine.send(
            RequestSpec(url="http://example.com/start", max_redirects=3)
        )

    assert "too many redirects" in (response.error or "")


async def test_reports_redirect_missing_location_header():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302)

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/")

    assert "Location" in (response.error or "")


async def test_retries_then_fails_on_persistent_timeout():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        raise httpx.ReadTimeout("simulated", request=request)

    async with _engine(handler, max_retries=1) as engine:
        response = await engine.get("http://example.com/")

    assert "timeout" in (response.error or "")
    assert counter["n"] == 2  # initial attempt + 1 retry
    assert engine.metrics.requests_failed == 1


async def test_recovers_when_a_retry_succeeds():
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        if counter["n"] == 1:
            raise httpx.ConnectError("simulated", request=request)
        return httpx.Response(200, text="recovered")

    async with _engine(handler, max_retries=2) as engine:
        response = await engine.get("http://example.com/")

    assert response.status_code == 200
    assert engine.metrics.requests_failed == 0


async def test_binary_content_is_not_decoded_to_text():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"\x89PNG\r\n", headers={"content-type": "image/png"}
        )

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/logo.png")

    assert response.status_code == 200
    assert response.text is None
    assert response.is_html is False


async def test_json_content_is_decoded_to_text():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"key": "value"})

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/api")

    assert response.text is not None
    assert "value" in response.text


async def test_oversized_body_is_truncated_and_flagged():
    big = "A" * 5000

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=big, headers={"content-type": "text/plain"})

    async with _engine(handler, max_response_bytes=1000) as engine:
        response = await engine.get("http://example.com/big")

    assert response.truncated is True
    assert len(response.text or "") == 1000
    assert response.body_bytes == 5000


async def test_metrics_accumulate_across_requests():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    async with _engine(handler) as engine:
        await engine.get("http://example.com/a")
        await engine.get("http://example.com/b")
        await engine.get("http://evil.com/c")  # blocked

    assert engine.metrics.requests_sent == 2
    assert engine.metrics.blocked_by_scope == 1
    assert engine.metrics.total_bytes > 0


async def test_using_engine_outside_context_manager_raises():
    engine = RequestEngine(_guard(), timeout=5, rate_limit=0, concurrency=1)
    with pytest.raises(RuntimeError):
        _ = engine.client


async def test_response_headers_are_lowercased():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", headers={"X-Frame-Options": "DENY"})

    async with _engine(handler) as engine:
        response = await engine.get("http://example.com/")

    assert response.headers["x-frame-options"] == "DENY"
