from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select

from app.database.repositories.base import BaseRepository
from app.models.enums import FindingStatus, Severity
from app.models.finding import Finding


class FindingRepository(BaseRepository[Finding]):
    model = Finding

    async def list_by_scan(
        self, scan_id: uuid.UUID, order_by_priority: bool = True
    ) -> Sequence[Finding]:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        if order_by_priority:
            # Unscored findings (priority_rank IS NULL) sort last rather than
            # first, since a NULL rank means "not yet risk-scored", not
            # "highest priority".
            stmt = stmt.order_by(Finding.priority_rank.asc().nulls_last())
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def list_by_severity(
        self, scan_id: uuid.UUID, severity: Severity
    ) -> Sequence[Finding]:
        result = await self.session.execute(
            select(Finding).where(
                Finding.scan_id == scan_id, Finding.severity == severity
            )
        )
        return result.scalars().all()

    async def update_status(
        self, finding_id: uuid.UUID, status: FindingStatus
    ) -> Finding | None:
        """Manually transition a finding's status (Section 17's "optional
        manual confirmation" -- e.g. an analyst marking a finding
        Confirmed, or False Positive after review).

        This is deliberately a plain status write with no workflow rules
        (e.g. "can't go from Resolved back to Open") -- enforcing a status
        state machine is an API/service-layer concern for whoever exposes
        this over HTTP (Milestone 11), not the repository's job.
        """
        finding = await self.get(finding_id)
        if finding is None:
            return None
        finding.status = status
        await self.session.flush()
        return finding
