from __future__ import annotations

import httpx
import pytest

from app.crawler.robots import RobotsPolicy

pytestmark = pytest.mark.asyncio

_ROBOTS_TXT = "\n".join(
    [
        "User-agent: *",
        "Disallow: /admin",
        "Allow: /admin/public",
    ]
)


def _make_client(robots_body: str | None, status_code: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if robots_body is None:
            return httpx.Response(404)
        return httpx.Response(status_code, text=robots_body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_disabled_policy_allows_everything_without_fetching():
    policy = RobotsPolicy(respect_robots_txt=False)
    async with _make_client(_ROBOTS_TXT) as client:
        await policy.load("http://example.com/", client)
    assert policy.is_allowed("http://example.com/admin", "TestAgent") is True


async def test_enabled_policy_disallows_matching_path():
    policy = RobotsPolicy(respect_robots_txt=True)
    async with _make_client(_ROBOTS_TXT) as client:
        await policy.load("http://example.com/", client)
    assert policy.is_allowed("http://example.com/admin", "TestAgent") is False


async def test_enabled_policy_allows_more_specific_allow_rule():
    policy = RobotsPolicy(respect_robots_txt=True)
    async with _make_client(_ROBOTS_TXT) as client:
        await policy.load("http://example.com/", client)
    assert policy.is_allowed("http://example.com/admin/public", "TestAgent") is True


async def test_enabled_policy_allows_unlisted_paths():
    policy = RobotsPolicy(respect_robots_txt=True)
    async with _make_client(_ROBOTS_TXT) as client:
        await policy.load("http://example.com/", client)
    assert policy.is_allowed("http://example.com/blog", "TestAgent") is True


async def test_missing_robots_txt_allows_everything():
    policy = RobotsPolicy(respect_robots_txt=True)
    async with _make_client(None) as client:
        await policy.load("http://example.com/", client)
    assert policy.is_allowed("http://example.com/admin", "TestAgent") is True


async def test_is_allowed_before_load_defaults_to_allow():
    policy = RobotsPolicy(respect_robots_txt=True)
    assert policy.is_allowed("http://example.com/admin", "TestAgent") is True
