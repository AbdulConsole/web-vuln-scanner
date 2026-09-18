"""
Target-related Pydantic schemas.

These live outside app/api/ deliberately: TargetService (the domain layer)
depends on them directly for validation, and TargetService must not depend
on the API layer. Route handlers (added in Milestone 11) will import these
same schemas rather than redefining request/response shapes.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.config import get_settings
from app.core.url_utils import InvalidUrlError, extract_domain, is_valid_domain, normalize_url


class ScanConfig(BaseModel):
    """Per-target scan behaviour settings (Section 6/19).

    Defaults are pulled from application settings rather than hardcoded, so
    a deployment-wide policy change (e.g. lowering DEFAULT_CRAWL_DEPTH)
    takes effect for new targets without a code change.
    """

    crawl_depth: int = Field(
        default_factory=lambda: get_settings().DEFAULT_CRAWL_DEPTH, ge=0, le=25
    )
    request_rate: float = Field(
        default_factory=lambda: get_settings().RATE_LIMIT,
        gt=0,
        description="Max requests per second for scans of this target.",
    )
    concurrency: int = Field(default=5, ge=1, le=100)
    timeout: float = Field(
        default_factory=lambda: get_settings().REQUEST_TIMEOUT, gt=0
    )
    respect_robots_txt: bool = Field(
        default_factory=lambda: get_settings().RESPECT_ROBOTS_TXT
    )
    max_urls: int = Field(
        default_factory=lambda: get_settings().MAX_URLS_PER_SCAN, gt=0
    )
    # Empty list means "all registered detectors" -- resolved against the
    # detector registry at scan-start time (Milestone 6), not here, since
    # the registry doesn't exist yet in this milestone.
    enabled_detectors: list[str] = Field(default_factory=list)
    # Additional URLs to probe beyond what the HTML crawler discovers.
    # Essential for SPAs (Angular, React, Vue) where routes are handled
    # client-side and not visible as <a href> links in the initial HTML.
    seed_urls: list[str] = Field(default_factory=list)

    @field_validator("concurrency")
    @classmethod
    def _clamp_to_deployment_max_concurrency(cls, v: int) -> int:
        settings = get_settings()
        if v > settings.MAX_CONCURRENCY:
            raise ValueError(
                f"concurrency {v} exceeds this deployment's MAX_CONCURRENCY "
                f"({settings.MAX_CONCURRENCY})"
            )
        return v


class AuthConfig(BaseModel):
    """Authentication configuration for authenticated scanning.

    LIMITATION: this is stored as plain JSON on the Target row (see
    app/models/target.py) -- encryption at rest is not yet implemented.
    Do not put real production credentials here until that lands. For the
    same reason, TargetRead never serializes this back out (see below) --
    only a boolean flag indicating whether auth is configured.
    """

    type: Literal["none", "basic", "cookie", "bearer_token"] = "none"
    username: str | None = None
    password: str | None = None
    cookie_value: str | None = None
    bearer_token: str | None = None

    @model_validator(mode="after")
    def _require_fields_for_selected_type(self) -> AuthConfig:
        if self.type == "basic" and not (self.username and self.password):
            raise ValueError("auth type 'basic' requires both username and password")
        if self.type == "cookie" and not self.cookie_value:
            raise ValueError("auth type 'cookie' requires cookie_value")
        if self.type == "bearer_token" and not self.bearer_token:
            raise ValueError("auth type 'bearer_token' requires bearer_token")
        return self


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    base_url: str
    allowed_domains: list[str] = Field(default_factory=list)
    scan_config: ScanConfig = Field(default_factory=ScanConfig)
    auth_config: AuthConfig | None = None

    @field_validator("base_url")
    @classmethod
    def _normalize_base_url(cls, v: str) -> str:
        try:
            return normalize_url(v)
        except InvalidUrlError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("allowed_domains")
    @classmethod
    def _normalize_allowed_domains(cls, v: list[str]) -> list[str]:
        return _clean_and_dedupe_domains(v)

    @model_validator(mode="after")
    def _exclude_base_domain_from_allowed_domains(self) -> TargetCreate:
        # The base domain is already implicitly in scope (see
        # app.core.security.ScopePolicy) -- listing it again in
        # allowed_domains is redundant, so it's silently dropped rather
        # than rejected, to keep the common case (user pastes the same
        # domain twice) friction-free.
        base_domain = extract_domain(self.base_url)
        self.allowed_domains = [d for d in self.allowed_domains if d != base_domain]
        return self


class TargetUpdate(BaseModel):
    """Partial update: only fields explicitly provided are changed."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    allowed_domains: list[str] | None = None
    scan_config: ScanConfig | None = None
    auth_config: AuthConfig | None = None

    @field_validator("allowed_domains")
    @classmethod
    def _normalize_allowed_domains(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return _clean_and_dedupe_domains(v)


class TargetRead(BaseModel):
    id: uuid.UUID
    name: str
    base_url: str
    allowed_domains: list[str]
    scan_config: dict[str, Any]
    has_auth_config: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, target: Any) -> TargetRead:
        return cls(
            id=target.id,
            name=target.name,
            base_url=target.base_url,
            allowed_domains=target.allowed_domains,
            scan_config=target.scan_config,
            has_auth_config=target.auth_config is not None,
            created_at=target.created_at,
            updated_at=target.updated_at,
        )


def _clean_and_dedupe_domains(domains: list[str]) -> list[str]:
    normalized: list[str] = []
    for domain in domains:
        cleaned = domain.strip().lower().rstrip(".")
        if not is_valid_domain(cleaned):
            raise ValueError(f"'{domain}' is not a valid domain")
        normalized.append(cleaned)

    seen: set[str] = set()
    deduped: list[str] = []
    for d in normalized:
        if d not in seen:
            seen.add(d)
            deduped.append(d)
    return deduped
