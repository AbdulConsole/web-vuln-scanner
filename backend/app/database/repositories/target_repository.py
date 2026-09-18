from __future__ import annotations

from sqlalchemy import select

from app.database.repositories.base import BaseRepository
from app.models.target import Target


class TargetRepository(BaseRepository[Target]):
    model = Target

    async def get_by_name(self, name: str) -> Target | None:
        result = await self.session.execute(select(Target).where(Target.name == name))
        return result.scalar_one_or_none()

    async def get_by_base_url(self, base_url: str) -> Target | None:
        """Look up a target by its (already-normalized) base_url.

        Callers must pass a normalized URL (see app.core.url_utils) --
        this does a plain equality match, not a fuzzy comparison.
        """
        result = await self.session.execute(
            select(Target).where(Target.base_url == base_url)
        )
        return result.scalar_one_or_none()
