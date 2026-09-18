"""
Application configuration.

All runtime configuration is sourced from environment variables (optionally
via a .env file for local development). Nothing here should contain secrets
or environment-specific values hardcoded in source.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed application settings.

    Every field has a safe, conservative default so the application can be
    started for local development without any configuration, but production
    deployments are expected to override these via environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- General -----------------------------------------------------
    APP_NAME: str = "Intelligent Web Vulnerability Scanner"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = False

    # --- Database ------------------------------------------------------
    # SQLite by default for local development; swap to a postgresql+asyncpg
    # URL for production. The ORM layer must not depend on SQLite-specific
    # behaviour so this swap requires no code changes.
    DATABASE_URL: str = "sqlite+aiosqlite:///./scanner.db"

    # --- Logging ---------------------------------------------------------
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_JSON: bool = True

    # --- HTTP / scanning behaviour ----------------------------------------
    REQUEST_TIMEOUT: float = Field(default=10.0, gt=0)
    MAX_CONCURRENCY: int = Field(default=5, gt=0, le=100)
    DEFAULT_CRAWL_DEPTH: int = Field(default=3, ge=0, le=25)
    RATE_LIMIT: float = Field(
        default=5.0, gt=0, description="Max requests per second per scan"
    )
    MAX_URLS_PER_SCAN: int = Field(default=2000, gt=0)
    RESPECT_ROBOTS_TXT: bool = True

    # --- Security ----------------------------------------------------------
    # Networks the scanner is NEVER permitted to contact, regardless of
    # target configuration, unless explicitly overridden for a controlled
    # lab environment (see ALLOW_PRIVATE_NETWORK_TARGETS).
    BLOCKED_IP_NETWORKS: list[str] = [
        "169.254.169.254/32",  # cloud metadata endpoints
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    # Set true only in isolated lab/dev environments where scanning
    # localhost / private ranges is intentional (e.g. a vulnerable test app
    # running in the same Docker network).
    ALLOW_PRIVATE_NETWORK_TARGETS: bool = False

    SECRET_KEY: str = Field(
        default="change-me-in-production",
        description="Used for signing/encryption of stored auth configs",
    )

    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("BLOCKED_IP_NETWORKS", mode="before")
    @classmethod
    def _split_networks(cls, v):
        if isinstance(v, str):
            return [n.strip() for n in v.split(",") if n.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance.

    Cached so environment parsing happens once per process; tests can call
    ``get_settings.cache_clear()`` to force re-reading the environment.
    """
    return Settings()
