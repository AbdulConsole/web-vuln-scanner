"""
Scan domain service (Section 18).

Handles scan CRUD and state transitions. Does NOT orchestrate the scan
pipeline -- that's ScanRunner's job. This service is the data-access
layer for scans, analogous to TargetService for targets.
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError, ScanConflictError
from app.core.logging import get_logger
from app.database.repositories.scan_repository import ScanRepository
from app.database.repositories.target_repository import TargetRepository
from app.models.enums import ScanStatus
from app.models.scan import Scan

logger = get_logger(__name__)


class ScanService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.scan_repo = ScanRepository(session)
        self.target_repo = TargetRepository(session)

    async def create_scan(self, target_id: uuid.UUID) -> Scan:
        """Create a new scan for a target. Freezes the target's current
        scan_config as a config_snapshot on the scan row."""
        target = await self.target_repo.get(target_id)
        if target is None:
            raise NotFoundError(f"Target {target_id} not found")

        scan = Scan(
            target_id=target_id,
            status=ScanStatus.QUEUED,
            config_snapshot=target.scan_config or {},
        )
        await self.scan_repo.add(scan)
        await self.scan_repo.commit()
        logger.info(
            "Scan created",
            extra={"context": {"scan_id": str(scan.id), "target_id": str(target_id)}},
        )
        return scan

    async def get_scan(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.scan_repo.get(scan_id)
        if scan is None:
            raise NotFoundError(f"Scan {scan_id} not found")
        return scan

    async def list_scans(
        self,
        target_id: uuid.UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Sequence[Scan], int]:
        if target_id is not None:
            scans = await self.scan_repo.list_by_target(target_id)
            # Apply limit/offset manually since list_by_target returns all.
            total = len(scans)
            scans = list(scans)[offset : offset + limit]
        else:
            scans = await self.scan_repo.list(limit=limit, offset=offset)
            # Count total for pagination.
            result = await self.session.execute(select(func.count(Scan.id)))
            total = result.scalar_one()
        return scans, total

    async def update_scan_status(
        self, scan_id: uuid.UUID, status: ScanStatus, error: str | None = None
    ) -> Scan:
        """Update scan status with basic state-machine validation."""
        scan = await self.get_scan(scan_id)

        # Basic transition validation.
        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            raise ScanConflictError(
                f"Scan {scan_id} is already in terminal state '{scan.status.value}'"
            )

        scan.status = status
        if error is not None:
            scan.error = error
        if status == ScanStatus.RUNNING and scan.started_at is None:
            from datetime import datetime
            scan.started_at = datetime.now(UTC)
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            from datetime import datetime
            scan.finished_at = datetime.now(UTC)

        await self.scan_repo.commit()
        return scan
