"""
Enumerations shared across ORM models.

Stored as plain VARCHAR (native_enum=False on the SQLAlchemy Enum type used
in each model) rather than native database ENUM types, so that adding a new
member never requires an ALTER TYPE migration on PostgreSQL — only a Python
change plus a normal Alembic data/constraint migration if needed.
"""
from __future__ import annotations

from enum import Enum

from sqlalchemy import Enum as SqlEnum


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"


class ExposureLevel(str, Enum):
    """How accessible the vulnerable component is. Used as a risk factor by
    the risk engine (see docs/risk-model.md, added in Milestone 9)."""

    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class ParameterSource(str, Enum):
    QUERY = "query"
    BODY = "body"
    FORM = "form"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ReportFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


def _as_varchar_enum(enum_cls: type[Enum], name: str, length: int) -> SqlEnum:
    """Build a portable, non-native SQLAlchemy Enum column type.

    Centralized here so every model uses an identical column type for a
    given enum, rather than each model file redefining its own SqlEnum(...)
    call with slightly different kwargs.
    """
    return SqlEnum(
        enum_cls,
        name=name,
        native_enum=False,
        length=length,
        values_callable=lambda ec: [member.value for member in ec],
    )


SCAN_STATUS_COLUMN_TYPE = _as_varchar_enum(ScanStatus, "scan_status", 20)
SEVERITY_COLUMN_TYPE = _as_varchar_enum(Severity, "finding_severity", 20)
FINDING_STATUS_COLUMN_TYPE = _as_varchar_enum(FindingStatus, "finding_status", 20)
EXPOSURE_LEVEL_COLUMN_TYPE = _as_varchar_enum(ExposureLevel, "exposure_level", 20)
PARAMETER_SOURCE_COLUMN_TYPE = _as_varchar_enum(
    ParameterSource, "parameter_source", 10
)
HTTP_METHOD_COLUMN_TYPE = _as_varchar_enum(HttpMethod, "http_method", 10)
REPORT_FORMAT_COLUMN_TYPE = _as_varchar_enum(ReportFormat, "report_format", 10)
