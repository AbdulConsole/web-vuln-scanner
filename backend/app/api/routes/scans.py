"""
Scan API routes.
"""
from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db, get_session_factory
from app.models.enums import ScanStatus
from app.schemas.finding import FindingList, FindingRead
from app.schemas.scan import ScanList, ScanRead
from app.services.finding_service import FindingService
from app.services.scan_runner import run_scan
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scans", tags=["scans"])

# In-memory store of background tasks for cancellation.
_background_tasks: dict[uuid.UUID, asyncio.Task] = {}


def _get_service(session: AsyncSession = Depends(get_db)) -> ScanService:
    return ScanService(session)


@router.post("", response_model=ScanRead, status_code=201)
async def create_scan(
    target_id: uuid.UUID,
    service: ScanService = Depends(_get_service),
    session: AsyncSession = Depends(get_db),
):
    """Create and start a background scan for a target."""
    scan = await service.create_scan(target_id)

    # Start background scan.
    session_factory = get_session_factory()
    task = asyncio.create_task(run_scan(scan.id, session_factory))
    _background_tasks[scan.id] = task

    return ScanRead.from_model(scan)


@router.get("", response_model=ScanList)
async def list_scans(
    target_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    service: ScanService = Depends(_get_service),
):
    scans, total = await service.list_scans(
        target_id=target_id, limit=limit, offset=offset
    )
    return ScanList(
        items=[ScanRead.from_model(s) for s in scans],
        total=total,
    )


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(
    scan_id: uuid.UUID,
    service: ScanService = Depends(_get_service),
):
    scan = await service.get_scan(scan_id)
    return ScanRead.from_model(scan)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
async def cancel_scan(
    scan_id: uuid.UUID,
    service: ScanService = Depends(_get_service),
):
    """Cancel a running scan."""
    scan = await service.update_scan_status(scan_id, ScanStatus.CANCELLED)
    # Also cancel the background task if it exists.
    task = _background_tasks.get(scan_id)
    if task and not task.done():
        task.cancel()
    return ScanRead.from_model(scan)


@router.get("/{scan_id}/findings", response_model=FindingList)
async def list_scan_findings(
    scan_id: uuid.UUID,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_db),
):
    from app.models.enums import FindingStatus, Severity

    finding_service = FindingService(session)
    severity_enum = Severity(severity) if severity else None
    status_enum = FindingStatus(status) if status else None
    findings, total = await finding_service.list_findings(
        scan_id=scan_id,
        severity=severity_enum,
        status=status_enum,
        limit=limit,
        offset=offset,
    )
    return FindingList(
        items=[FindingRead.from_model(f) for f in findings],
        total=total,
    )
