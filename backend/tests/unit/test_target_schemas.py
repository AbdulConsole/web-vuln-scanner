from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import get_settings
from app.schemas.target import AuthConfig, ScanConfig, TargetCreate, TargetUpdate

@pytest.fixture(autouse=True)
def _clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_scan_config_defaults_come_from_settings():
    settings = get_settings()
    config = ScanConfig()
    assert config.crawl_depth == settings.DEFAULT_CRAWL_DEPTH
    assert config.request_rate == settings.RATE_LIMIT
    assert config.timeout == settings.REQUEST_TIMEOUT
    assert config.respect_robots_txt == settings.RESPECT_ROBOTS_TXT


def test_scan_config_rejects_concurrency_above_deployment_max():
    settings = get_settings()
    with pytest.raises(ValidationError):
        ScanConfig(concurrency=settings.MAX_CONCURRENCY + 50)


def test_scan_config_rejects_negative_crawl_depth():
    with pytest.raises(ValidationError):
        ScanConfig(crawl_depth=-1)


def test_auth_config_none_type_requires_nothing():
    config = AuthConfig()
    assert config.type == "none"


def test_auth_config_basic_requires_username_and_password():
    with pytest.raises(ValidationError):
        AuthConfig(type="basic", username="admin")
    config = AuthConfig(type="basic", username="admin", password="secret")
    assert config.username == "admin"


def test_auth_config_cookie_requires_cookie_value():
    with pytest.raises(ValidationError):
        AuthConfig(type="cookie")
    config = AuthConfig(type="cookie", cookie_value="session=abc")
    assert config.cookie_value == "session=abc"


def test_auth_config_bearer_requires_token():
    with pytest.raises(ValidationError):
        AuthConfig(type="bearer_token")
    config = AuthConfig(type="bearer_token", bearer_token="xyz")
    assert config.bearer_token == "xyz"


def test_target_create_normalizes_base_url():
    payload = TargetCreate(name="Test App", base_url="HTTP://Example.COM:80/")
    assert payload.base_url == "http://example.com/"


def test_target_create_normalizes_and_dedupes_allowed_domains():
    payload = TargetCreate(
        name="Test App",
        base_url="http://example.com",
        allowed_domains=["Staging.Example.com", "staging.example.com.", "staging.example.com"],
    )
    assert payload.allowed_domains == ["staging.example.com"]


def test_target_create_excludes_base_domain_from_allowed_domains():
    payload = TargetCreate(
        name="Test App",
        base_url="http://example.com",
        allowed_domains=["example.com", "staging.example.com"],
    )
    assert payload.allowed_domains == ["staging.example.com"]


def test_target_create_rejects_invalid_domain():
    with pytest.raises(ValidationError):
        TargetCreate(
            name="Test App",
            base_url="http://example.com",
            allowed_domains=["http://not-a-domain.com"],
        )


def test_target_create_rejects_invalid_base_url():
    with pytest.raises(ValidationError):
        TargetCreate(name="Test App", base_url="not-a-url")


def test_target_update_allows_partial_fields():
    payload = TargetUpdate(name="Renamed")
    assert payload.name == "Renamed"
    assert payload.allowed_domains is None
    assert payload.scan_config is None
