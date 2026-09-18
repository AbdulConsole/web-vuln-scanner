from __future__ import annotations

from app.core.config import get_settings


def test_settings_have_safe_defaults():
    settings = get_settings()
    assert settings.ALLOW_PRIVATE_NETWORK_TARGETS is False
    assert settings.RESPECT_ROBOTS_TXT is True
    assert settings.MAX_CONCURRENCY <= 100
    assert settings.REQUEST_TIMEOUT > 0


def test_cors_origins_parsed_from_comma_separated_string(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://a.com, http://b.com")
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.CORS_ORIGINS == ["http://a.com", "http://b.com"]
    get_settings.cache_clear()


def test_blocked_networks_include_metadata_and_loopback():
    settings = get_settings()
    assert "169.254.169.254/32" in settings.BLOCKED_IP_NETWORKS
    assert "127.0.0.0/8" in settings.BLOCKED_IP_NETWORKS
