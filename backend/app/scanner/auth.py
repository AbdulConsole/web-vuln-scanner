"""
Authenticated-scanning support.

Translates a target's stored AuthConfig into the default headers/cookies a
RequestEngine should attach to every request. Kept separate from the engine
itself so the engine has no knowledge of the Target model or auth schema --
it just receives plain header/cookie dicts.

SECURITY NOTE: the returned values are credentials. They are passed to
RequestEngine as defaults and are never written to logs (the logging
redaction filter in app/core/logging.py strips Authorization/Cookie keys)
and must never be copied into evidence records -- the evidence sanitizer
(Milestone 8) is responsible for enforcing that on the storage side.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuthMaterial:
    headers: dict[str, str]
    cookies: dict[str, str]

    @property
    def is_authenticated(self) -> bool:
        return bool(self.headers or self.cookies)


def build_auth_material(auth_config: Mapping[str, Any] | None) -> AuthMaterial:
    """Build headers/cookies from a target's auth_config dict.

    Accepts the plain dict form stored on Target.auth_config (rather than
    the Pydantic AuthConfig) so this works equally for a freshly validated
    payload and a row loaded from the database.
    """
    if not auth_config:
        return AuthMaterial(headers={}, cookies={})

    auth_type = auth_config.get("type", "none")

    if auth_type == "none":
        return AuthMaterial(headers={}, cookies={})

    if auth_type == "basic":
        username = auth_config.get("username") or ""
        password = auth_config.get("password") or ""
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        return AuthMaterial(headers={"Authorization": f"Basic {encoded}"}, cookies={})

    if auth_type == "bearer_token":
        token = auth_config.get("bearer_token") or ""
        return AuthMaterial(headers={"Authorization": f"Bearer {token}"}, cookies={})

    if auth_type == "cookie":
        raw = auth_config.get("cookie_value") or ""
        return AuthMaterial(headers={}, cookies=_parse_cookie_string(raw))

    return AuthMaterial(headers={}, cookies={})


def _parse_cookie_string(raw: str) -> dict[str, str]:
    """Parse a 'k=v; k2=v2' cookie header value into a dict.

    Malformed segments (no '=') are skipped rather than raising, so one bad
    cookie in an operator-supplied string doesn't break the whole scan.
    """
    cookies: dict[str, str] = {}
    for segment in raw.split(";"):
        segment = segment.strip()
        if not segment or "=" not in segment:
            continue
        name, _, value = segment.partition("=")
        name = name.strip()
        if name:
            cookies[name] = value.strip()
    return cookies
