from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select

from app.database.repositories.base import BaseRepository
from app.models.enums import ScanStatus
from app.models.scan import Scan


class ScanRepository(BaseRepository[Scan]):
    model = Scan

    async def list_by_target(self, target_id: uuid.UUID) -> Sequence[Scan]:
        result = await self.session.execute(
            select(Scan)
            .where(Scan.target_id == target_id)
            .order_by(Scan.created_at.desc())
        )
        return result.scalars().all()

    async def list_by_status(self, status: ScanStatus) -> Sequence[Scan]:
        result = await self.session.execute(select(Scan).where(Scan.status == status))
        return result.scalars().all()
