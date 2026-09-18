from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_health_endpoint_returns_ok(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "app_name" in body
    assert "version" in body
    assert body["environment"] in {"development", "testing", "production"}
