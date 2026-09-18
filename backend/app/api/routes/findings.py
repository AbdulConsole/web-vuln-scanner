"""
Finding API routes.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.database import get_db
from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.schemas.finding import FindingDetail, FindingRead, FindingStatusUpdate
from app.services.finding_service import FindingService

router = APIRouter(prefix="/findings", tags=["findings"])


def _get_service(session: AsyncSession = Depends(get_db)) -> FindingService:
    return FindingService(session)


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: uuid.UUID,
    service: FindingService = Depends(_get_service),
    session: AsyncSession = Depends(get_db),
):
    """Get a finding with full evidence and risk breakdown."""
    result = await session.execute(
        select(Finding)
        .options(
            selectinload(Finding.evidence_items),
            selectinload(Finding.risk_breakdowns),
        )
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        from app.core.exceptions import NotFoundError
        raise NotFoundError(f"Finding {finding_id} not found")
    return FindingDetail.from_model_with_details(finding)


@router.patch("/{finding_id}/status", response_model=FindingRead)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    service: FindingService = Depends(_get_service),
):
    status = FindingStatus(payload.status)
    finding = await service.update_finding_status(finding_id, status)
    return FindingRead.from_model(finding)
