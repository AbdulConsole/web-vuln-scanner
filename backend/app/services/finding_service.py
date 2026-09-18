"""
Finding domain service.

Handles finding queries and status updates.
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.database.repositories.finding_repository import FindingRepository
from app.models.enums import FindingStatus, Severity
from app.models.finding import Finding


class FindingService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.finding_repo = FindingRepository(session)

    async def get_finding(self, finding_id: uuid.UUID) -> Finding:
        finding = await self.finding_repo.get(finding_id)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        return finding

    async def list_findings(
        self,
        scan_id: uuid.UUID,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[Sequence[Finding], int]:
        if severity is not None:
            findings = await self.finding_repo.list_by_severity(scan_id, severity)
        else:
            findings = await self.finding_repo.list_by_scan(scan_id)

        # Apply status filter in-memory (repo doesn't have a combined filter yet).
        if status is not None:
            findings = [f for f in findings if f.status == status]

        total = len(findings)
        findings = list(findings)[offset : offset + limit]
        return findings, total

    async def update_finding_status(
        self, finding_id: uuid.UUID, status: FindingStatus
    ) -> Finding:
        finding = await self.finding_repo.update_status(finding_id, status)
        if finding is None:
            raise NotFoundError(f"Finding {finding_id} not found")
        await self.finding_repo.commit()
        return finding
