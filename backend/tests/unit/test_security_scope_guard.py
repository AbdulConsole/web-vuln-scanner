from __future__ import annotations

import pytest

from app.core.config import get_settings
from app.core.exceptions import ScopeViolationError, UnsafeTargetError
from app.core.security import ScopeGuard, ScopePolicy


@pytest.fixture
def policy():
    return ScopePolicy(base_domain="example.com", allowed_domains=("staging.example.org",))


def test_host_within_base_domain_is_in_scope(policy):
    guard = ScopeGuard(policy)
    guard.check_domain_scope("https://example.com/login")


def test_subdomain_of_base_domain_is_in_scope(policy):
    guard = ScopeGuard(policy)
    guard.check_domain_scope("https://app.example.com/dashboard")


def test_allowed_additional_domain_is_in_scope(policy):
    guard = ScopeGuard(policy)
    guard.check_domain_scope("https://staging.example.org/api")


def test_unrelated_domain_is_rejected(policy):
    guard = ScopeGuard(policy)
    with pytest.raises(ScopeViolationError):
        guard.check_domain_scope("https://evil.com/steal")


def test_lookalike_domain_is_rejected(policy):
    """'notexample.com' must not match 'example.com' via naive substring
    matching — this guards against a classic scope-check bypass."""
    guard = ScopeGuard(policy)
    with pytest.raises(ScopeViolationError):
        guard.check_domain_scope("https://notexample.com/")


def test_domain_as_suffix_without_dot_is_rejected(policy):
    """'evilexample.com' should not match 'example.com'."""
    guard = ScopeGuard(policy)
    with pytest.raises(ScopeViolationError):
        guard.check_domain_scope("https://evilexample.com/")


def test_private_ip_literal_is_blocked_by_default():
    get_settings.cache_clear()
    policy = ScopePolicy(base_domain="169.254.169.254")
    guard = ScopeGuard(policy)
    with pytest.raises(UnsafeTargetError):
        guard.check_network_safety("http://169.254.169.254/latest/meta-data/")


def test_loopback_ip_literal_is_blocked_by_default():
    policy = ScopePolicy(base_domain="127.0.0.1")
    guard = ScopeGuard(policy)
    with pytest.raises(UnsafeTargetError):
        guard.check_network_safety("http://127.0.0.1:8080/")


def test_private_network_allowed_when_lab_mode_enabled(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_NETWORK_TARGETS", "true")
    get_settings.cache_clear()
    policy = ScopePolicy(base_domain="127.0.0.1")
    guard = ScopeGuard(policy)
    # Should not raise
    guard.check_network_safety("http://127.0.0.1:8080/")
    get_settings.cache_clear()
