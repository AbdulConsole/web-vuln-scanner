from __future__ import annotations

import pytest

from app.core.url_utils import InvalidUrlError, extract_domain, is_valid_domain, normalize_url


def test_normalize_lowercases_scheme_and_host():
    assert normalize_url("HTTP://Example.COM/Path") == "http://example.com/Path"


def test_normalize_strips_default_http_port():
    assert normalize_url("http://example.com:80/login") == "http://example.com/login"


def test_normalize_strips_default_https_port():
    assert normalize_url("https://example.com:443/login") == "https://example.com/login"


def test_normalize_keeps_non_default_port():
    assert normalize_url("http://example.com:8080/login") == "http://example.com:8080/login"


def test_normalize_collapses_empty_path_to_slash():
    assert normalize_url("http://example.com") == "http://example.com/"


def test_normalize_removes_fragment_by_default():
    assert normalize_url("http://example.com/page#section") == "http://example.com/page"


def test_normalize_can_keep_fragment():
    result = normalize_url("http://example.com/page#section", strip_fragment=False)
    assert result == "http://example.com/page#section"


def test_normalize_sorts_query_parameters():
    a = normalize_url("http://example.com/search?b=2&a=1")
    b = normalize_url("http://example.com/search?a=1&b=2")
    assert a == b == "http://example.com/search?a=1&b=2"


def test_normalize_rejects_missing_scheme():
    with pytest.raises(InvalidUrlError):
        normalize_url("example.com/login")


def test_normalize_rejects_unsupported_scheme():
    with pytest.raises(InvalidUrlError):
        normalize_url("ftp://example.com/file")


def test_normalize_rejects_url_with_no_host():
    with pytest.raises(InvalidUrlError):
        normalize_url("http:///path-only")


def test_extract_domain_returns_lowercased_hostname():
    assert extract_domain("HTTP://Example.COM:8080/x") == "example.com"


@pytest.mark.parametrize(
    "domain",
    ["example.com", "sub.example.com", "localhost", "127.0.0.1", "10.0.0.5", "a-b.co"],
)
def test_is_valid_domain_accepts_reasonable_values(domain):
    assert is_valid_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "http://example.com",
        "example.com/path",
        "exa mple.com",
        "-example.com",
        "example-.com",
        "a" * 64 + ".com",
    ],
)
def test_is_valid_domain_rejects_malformed_values(domain):
    assert is_valid_domain(domain) is False
