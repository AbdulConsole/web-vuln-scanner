"""
Report-related Pydantic schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class ReportCreate(BaseModel):
    format: Literal["json", "html", "pdf"] = "json"


class ReportRead(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    format: str
    generated_at: datetime
    storage_path: str

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, report: Any) -> ReportRead:
        return cls(
            id=report.id,
            scan_id=report.scan_id,
            format=report.format.value if hasattr(report.format, "value") else report.format,
            generated_at=report.generated_at,
            storage_path=report.storage_path,
        )


class ReportList(BaseModel):
    items: list[ReportRead]
    total: int
