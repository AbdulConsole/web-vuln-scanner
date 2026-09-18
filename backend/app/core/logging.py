"""
Structured logging configuration.

Logs are emitted as JSON lines in production (machine-parseable) and as
readable text in local development. A redaction filter strips known-sensitive
field names before any record is emitted, as a defense-in-depth backstop on
top of evidence-layer sanitization.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from app.core.config import get_settings
from app.core.redaction import redact


class RedactionFilter(logging.Filter):
    """Removes sensitive values from structured log 'extra' payloads."""

    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "context") and isinstance(record.context, dict):
            record.context = redact(record.context)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        context = getattr(record, "context", None)
        if context:
            payload["context"] = context
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Configure the root logger once at application startup."""
    settings = get_settings()
    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL)

    # Avoid duplicate handlers on reload
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactionFilter())

    if settings.LOG_JSON:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
            )
        )

    root.addHandler(handler)

    # Quiet noisy third-party loggers by default
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
