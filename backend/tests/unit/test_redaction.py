from __future__ import annotations

from app.core.redaction import is_sensitive_key, redact


def test_is_sensitive_key_matches_exact_names():
    for key in ["password", "token", "secret", "cookie", "session", "api_key"]:
        assert is_sensitive_key(key) is True


def test_is_sensitive_key_matches_substrings():
    for key in ["user_password", "session_cookie", "X-Api-Key", "auth_token"]:
        assert is_sensitive_key(key) is True


def test_is_sensitive_key_does_not_match_unrelated_names():
    for key in ["username", "email", "url", "status_code", "title"]:
        assert is_sensitive_key(key) is False


def test_redact_replaces_sensitive_values_in_flat_dict():
    result = redact({"username": "alice", "password": "hunter2"})
    assert result == {"username": "alice", "password": "***REDACTED***"}


def test_redact_recurses_into_nested_dicts():
    result = redact({"user": {"name": "alice", "session_token": "abc123"}})
    assert result["user"]["name"] == "alice"
    assert result["user"]["session_token"] == "***REDACTED***"


def test_redact_recurses_into_lists_of_dicts():
    result = redact({"headers": [{"name": "Authorization", "value": "Bearer xyz"}]})
    # "name" and "value" aren't sensitive keys themselves -- only the
    # actual key holding the secret would be, e.g. a dict shaped
    # {"authorization": "..."} rather than {"name": "Authorization", ...}.
    # This test documents that key-based redaction doesn't inspect values.
    assert result["headers"][0]["value"] == "Bearer xyz"


def test_redact_leaves_non_sensitive_data_untouched():
    original = {"url": "http://example.com", "status": 200, "items": [1, 2, 3]}
    assert redact(original) == original


def test_redact_does_not_mutate_the_original():
    original = {"password": "hunter2"}
    redact(original)
    assert original["password"] == "hunter2"
