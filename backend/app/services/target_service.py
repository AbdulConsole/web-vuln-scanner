"""
Target management service (Section 6).

This is the domain layer for targets: route handlers (Milestone 11) will
call this rather than touching TargetRepository or the ORM model directly.
Putting validation and scope-safety checks here — not in the API layer —
means the same guarantees apply regardless of caller (REST API, a future
CLI, or a background job), and keeps FastAPI-specific concerns out of the
domain logic entirely.
"""
from __future__ import annotations

import asyncio
import uuid
from collections.abc import Sequence

from app.core.exceptions import NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.core.security import ScopeGuard, ScopePolicy
from app.core.url_utils import extract_domain
from app.database.repositories.target_repository import TargetRepository
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetUpdate

logger = get_logger(__name__)


class TargetService:
    def __init__(self, repository: TargetRepository):
        self.repository = repository

    async def create_target(self, payload: TargetCreate) -> Target:
        if await self.repository.get_by_name(payload.name) is not None:
            raise ValidationFailedError(
                f"A target named '{payload.name}' already exists."
            )

        # base_url is already normalized by TargetCreate's validator, so
        # this is a direct equality lookup -- prevents two Target rows
        # silently pointing at the same site (Section 6/7 "duplicate URL
        # prevention"), which would make authorization scope ambiguous.
        duplicate = await self.repository.get_by_base_url(payload.base_url)
        if duplicate is not None:
            raise ValidationFailedError(
                f"A target with base_url '{payload.base_url}' already exists "
                f"(target '{duplicate.name}')."
            )

        await self._validate_network_safety(payload.base_url, payload.allowed_domains)

        target = Target(
            name=payload.name,
            base_url=payload.base_url,
            allowed_domains=payload.allowed_domains,
            scan_config=payload.scan_config.model_dump(),
            auth_config=(
                payload.auth_config.model_dump() if payload.auth_config else None
            ),
        )
        await self.repository.add(target)
        await self.repository.commit()
        logger.info(
            "Target created",
            extra={"context": {"target_id": str(target.id), "base_url": target.base_url}},
        )
        return target

    async def get_target(self, target_id: uuid.UUID) -> Target:
        target = await self.repository.get(target_id)
        if target is None:
            raise NotFoundError(f"Target '{target_id}' not found.")
        return target

    async def list_targets(self, limit: int = 100, offset: int = 0) -> Sequence[Target]:
        return await self.repository.list(limit=limit, offset=offset)

    async def update_target(self, target_id: uuid.UUID, payload: TargetUpdate) -> Target:
        target = await self.get_target(target_id)

        if payload.name is not None and payload.name != target.name:
            existing = await self.repository.get_by_name(payload.name)
            if existing is not None and existing.id != target.id:
                raise ValidationFailedError(
                    f"A target named '{payload.name}' already exists."
                )
            target.name = payload.name

        if payload.allowed_domains is not None:
            base_domain = extract_domain(target.base_url)
            allowed = [d for d in payload.allowed_domains if d != base_domain]
            await self._validate_network_safety(target.base_url, allowed)
            target.allowed_domains = allowed

        if payload.scan_config is not None:
            target.scan_config = payload.scan_config.model_dump()

        if payload.auth_config is not None:
            target.auth_config = payload.auth_config.model_dump()

        await self.repository.commit()
        logger.info("Target updated", extra={"context": {"target_id": str(target.id)}})
        return target

    async def delete_target(self, target_id: uuid.UUID) -> None:
        target = await self.get_target(target_id)
        await self.repository.delete(target)
        await self.repository.commit()
        logger.info("Target deleted", extra={"context": {"target_id": str(target_id)}})

    async def _validate_network_safety(
        self, base_url: str, allowed_domains: list[str]
    ) -> None:
        """Reject targets that resolve into a blocked network range.

        ScopeGuard.check_network_safety performs a blocking DNS resolution
        (socket.getaddrinfo), so it's dispatched to a worker thread via
        asyncio.to_thread rather than called directly on the event loop.
        Raises ScopeViolationError / UnsafeTargetError (both ScannerError
        subclasses with their own HTTP status codes) which propagate
        unchanged to the caller.
        """
        base_domain = extract_domain(base_url)
        policy = ScopePolicy(base_domain=base_domain, allowed_domains=tuple(allowed_domains))
        guard = ScopeGuard(policy)
        await asyncio.to_thread(guard.check_network_safety, base_url)
