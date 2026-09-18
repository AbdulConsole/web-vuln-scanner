from __future__ import annotations

import base64

from app.scanner.auth import build_auth_material


def test_none_type_produces_no_auth_material():
    material = build_auth_material({"type": "none"})
    assert material.headers == {}
    assert material.cookies == {}
    assert material.is_authenticated is False


def test_missing_config_produces_no_auth_material():
    material = build_auth_material(None)
    assert material.is_authenticated is False


def test_basic_auth_builds_encoded_authorization_header():
    material = build_auth_material(
        {"type": "basic", "username": "alice", "password": "s3cret"}
    )
    expected = base64.b64encode(b"alice:s3cret").decode()
    assert material.headers["Authorization"] == f"Basic {expected}"
    assert material.is_authenticated is True


def test_bearer_token_builds_authorization_header():
    material = build_auth_material({"type": "bearer_token", "bearer_token": "tok123"})
    assert material.headers["Authorization"] == "Bearer tok123"


def test_cookie_auth_parses_single_cookie():
    material = build_auth_material({"type": "cookie", "cookie_value": "session=abc123"})
    assert material.cookies == {"session": "abc123"}


def test_cookie_auth_parses_multiple_cookies():
    material = build_auth_material(
        {"type": "cookie", "cookie_value": "session=abc; csrf=xyz; theme=dark"}
    )
    assert material.cookies == {"session": "abc", "csrf": "xyz", "theme": "dark"}


def test_cookie_auth_skips_malformed_segments():
    material = build_auth_material(
        {"type": "cookie", "cookie_value": "session=abc; garbage; =novalue; ok=yes"}
    )
    assert material.cookies == {"session": "abc", "ok": "yes"}


def test_unknown_auth_type_produces_no_material():
    material = build_auth_material({"type": "something_unsupported"})
    assert material.is_authenticated is False
