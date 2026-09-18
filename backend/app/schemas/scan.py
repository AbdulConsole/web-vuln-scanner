"""
Scan-related Pydantic schemas.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ScanCreate(BaseModel):
    """Request body for creating a scan -- just the target_id. The scan
    configuration is frozen from the target's current scan_config at
    scan-start time (see ScanService)."""
    pass


class ScanRead(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    status: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    urls_crawled: int = 0
    requests_sent: int = 0
    duration_seconds: float | None = None
    error: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, scan: Any) -> ScanRead:
        return cls(
            id=scan.id,
            target_id=scan.target_id,
            status=scan.status.value if hasattr(scan.status, "value") else scan.status,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            urls_crawled=scan.urls_crawled,
            requests_sent=scan.requests_sent,
            duration_seconds=scan.duration_seconds,
            error=scan.error,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
        )


class ScanList(BaseModel):
    """Paginated list of scans."""
    items: list[ScanRead]
    total: int
