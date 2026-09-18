"""
Shared sensitive-data redaction logic.

Used by both structured logging (app/core/logging.py) and evidence
sanitization (app/evidence/sanitizer.py) so "what counts as sensitive" is
defined in exactly one place rather than drifting between the two --
having the log redaction filter and the evidence sanitizer disagree about
what a "secret" looks like would be its own quiet security bug.

Substring matching (not exact-match) is used deliberately: an exact-match
list would miss "user_password", "session_cookie", "x_api_key", etc. The
tradeoff is a small chance of over-redacting a field whose name merely
contains one of these substrings for unrelated reasons -- an acceptable
trade given the cost of under-redacting a real secret is much higher.
"""
from __future__ import annotations

from typing import Any

REDACTED_PLACEHOLDER = "***REDACTED***"

# Substrings (checked case-insensitively) that mark a dict key as likely
# holding sensitive data.
SENSITIVE_KEY_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "authorization",
        "cookie",
        "session",
        "token",
        "api_key",
        "apikey",
        "secret",
        "private_key",
        "credit_card",
        "ssn",
    }
)


def is_sensitive_key(key: str) -> bool:
    key_lower = key.lower()
    return any(marker in key_lower for marker in SENSITIVE_KEY_SUBSTRINGS)


def redact(value: Any) -> Any:
    """Recursively redact dict values whose key looks sensitive.

    Lists are recursed into (so a sensitive value nested inside a list of
    dicts is still caught); non-dict, non-list values are returned as-is.
    """
    if isinstance(value, dict):
        return {
            k: (REDACTED_PLACEHOLDER if is_sensitive_key(str(k)) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
