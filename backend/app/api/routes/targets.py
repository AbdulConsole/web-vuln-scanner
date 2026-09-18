"""
Target API routes.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.database import get_db
from app.schemas.target import TargetCreate, TargetRead, TargetUpdate
from app.services.target_service import TargetService

router = APIRouter(prefix="/targets", tags=["targets"])


def _get_service(session: AsyncSession = Depends(get_db)) -> TargetService:
    return TargetService(session)


@router.get("", response_model=list[TargetRead])
async def list_targets(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    service: TargetService = Depends(_get_service),
):
    targets = await service.list_targets(limit=limit, offset=offset)
    return [TargetRead.from_model(t) for t in targets]


@router.post("", response_model=TargetRead, status_code=201)
async def create_target(
    payload: TargetCreate,
    service: TargetService = Depends(_get_service),
):
    target = await service.create_target(payload)
    return TargetRead.from_model(target)


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(
    target_id: uuid.UUID,
    service: TargetService = Depends(_get_service),
):
    target = await service.get_target(target_id)
    return TargetRead.from_model(target)


@router.put("/{target_id}", response_model=TargetRead)
async def update_target(
    target_id: uuid.UUID,
    payload: TargetUpdate,
    service: TargetService = Depends(_get_service),
):
    target = await service.update_target(target_id, payload)
    return TargetRead.from_model(target)


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: uuid.UUID,
    service: TargetService = Depends(_get_service),
):
    await service.delete_target(target_id)
