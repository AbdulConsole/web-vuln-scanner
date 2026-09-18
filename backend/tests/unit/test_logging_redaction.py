from __future__ import annotations

import logging

from app.core.logging import RedactionFilter


def _make_record(context: dict) -> logging.LogRecord:
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="test message", args=(), exc_info=None,
    )
    record.context = context
    return record


def test_redaction_filter_redacts_sensitive_context_fields():
    record = _make_record({"url": "http://example.com/", "password": "hunter2"})
    RedactionFilter().filter(record)
    assert record.context["url"] == "http://example.com/"
    assert record.context["password"] == "***REDACTED***"


def test_redaction_filter_ignores_records_without_context():
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname=__file__, lineno=1,
        msg="no context here", args=(), exc_info=None,
    )
    # Must not raise even though record.context doesn't exist.
    assert RedactionFilter().filter(record) is True
