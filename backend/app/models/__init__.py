"""
Importing this package (or any single name from it) has the side effect of
registering every model class on ``Base.metadata``. Anything that needs the
full schema present -- ``Base.metadata.create_all``, Alembic's env.py, or
tests using an in-memory database -- should ``import app.models`` (even if
unused) before touching the metadata.
"""
from __future__ import annotations

from app.models.attack_surface import Form, Parameter, Url
from app.models.finding import Evidence, Finding, RiskScoreBreakdown
from app.models.report import Report
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User

__all__ = [
    "Target",
    "Scan",
    "Url",
    "Form",
    "Parameter",
    "Finding",
    "Evidence",
    "RiskScoreBreakdown",
    "Report",
    "User",
]
