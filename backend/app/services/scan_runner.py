"""
Background scan orchestrator.

Runs the full scan pipeline as an asyncio task:
  1. Validate target and create request engine
  2. Crawl the target → attack surface (Url/Form/Parameter rows)
  3. Run all detectors against the attack surface
  4. Persist findings + evidence
  5. Score findings with risk engine
  6. Rank findings with prioritizer
  7. Mark scan complete (or failed on error)

This module wires together every subsystem built in Milestones 4-10.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.logging import get_logger
from app.core.security import ScopeGuard, ScopePolicy
from app.crawler.crawler import Crawler
from app.detectors.base import DetectionContext
from app.detectors.manager import DetectorManager, discover_builtin_detectors
from app.evidence.collector import EvidenceCollector
from app.models.attack_surface import Form, Parameter, Url
from app.models.enums import ScanStatus
from app.models.scan import Scan
from app.models.target import Target
from app.risk.engine import RiskEngine
from app.risk.prioritizer import Prioritizer
from app.scanner.request_engine import RequestEngine

logger = get_logger(__name__)


async def _persist_attack_surface(
    session: AsyncSession,
    scan_id: uuid.UUID,
    crawl_summary,
) -> None:
    """Translate crawler dataclasses into Url/Form/Parameter ORM rows."""
    for crawled_url in crawl_summary.urls:
        url_row = Url(
            scan_id=scan_id,
            url=crawled_url.url,
            method=crawled_url.method,
            status_code=crawled_url.status_code,
            content_type=crawled_url.content_type,
            response_time_ms=crawled_url.response_time_ms,
            depth=crawled_url.depth,
            source_url=crawled_url.source_url,
        )
        session.add(url_row)
        await session.flush()

        for discovered_form in crawled_url.forms:
            form_row = Form(
                url_id=url_row.id,
                action=discovered_form.action,
                method=discovered_form.method,
                inputs=discovered_form.inputs,
            )
            session.add(form_row)

        for discovered_param in crawled_url.parameters:
            param_row = Parameter(
                url_id=url_row.id,
                name=discovered_param.name,
                source=discovered_param.source,
                sample_value=discovered_param.sample_value,
            )
            session.add(param_row)

    await session.flush()


async def run_scan(
    scan_id: uuid.UUID,
    session_factory: async_sessionmaker[AsyncSession],
    cancellation_token: asyncio.Event | None = None,
) -> None:
    """Execute the full scan pipeline. Called as a background task."""
    async with session_factory() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found", scan_id)
            return

        target = await session.get(Target, scan.target_id)
        if target is None:
            logger.error("Target %s not found for scan %s", scan.target_id, scan_id)
            await _mark_failed(session, scan, "Target not found")
            return

        try:
            # Mark as running.
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(UTC)
            await session.commit()

            logger.info(
                "Scan started",
                extra={"context": {"scan_id": str(scan_id), "target_id": str(target.id)}},
            )

            # Build scope guard and request engine.
            from app.core.url_utils import extract_domain
            base_domain = extract_domain(target.base_url)
            scope_policy = ScopeGuard(ScopePolicy(
                base_domain=base_domain,
                allowed_domains=tuple(target.allowed_domains or []),
            ))
            scan_config = scan.config_snapshot or {}

            async with RequestEngine(
                scope_policy,
                timeout=scan_config.get("timeout", 10.0),
                rate_limit=scan_config.get("request_rate", 5.0),
                concurrency=scan_config.get("concurrency", 5),
            ) as engine:
                # Phase 1: Crawl.
                crawler = Crawler(
                    scope_guard=scope_policy,
                    base_url=target.base_url,
                    scan_config=scan_config,
                    request_engine=engine,
                )
                crawl_summary = await crawler.crawl(cancellation_token)

                if crawl_summary.cancelled:
                    await _mark_cancelled(session, scan)
                    return

                # Persist attack surface.
                await _persist_attack_surface(session, scan_id, crawl_summary)
                scan.urls_crawled = len(crawl_summary.urls)
                scan.requests_sent = crawl_summary.total_requests
                await session.commit()

                # Phase 2: Detect.
                discover_builtin_detectors()
                manager = DetectorManager.from_registry(
                    engine,
                    enabled=scan_config.get("enabled_detectors"),
                )
                detection_context = DetectionContext(
                    engine=engine,
                    crawl_summary=crawl_summary,
                    scan_config=scan_config,
                )
                detection_summary = await manager.run_all(detection_context)

                # Phase 3: Persist findings.
                collector = EvidenceCollector(session)
                findings = await collector.persist_all(scan_id, detection_summary.findings)

                # Phase 4: Score.
                risk_engine = RiskEngine(session)
                await risk_engine.score_all(findings)

                # Phase 5: Rank.
                prioritizer = Prioritizer(session)
                await prioritizer.rank_all(scan_id)

                # Mark complete.
                scan.status = ScanStatus.COMPLETED
                scan.finished_at = datetime.now(UTC)
                await session.commit()

                logger.info(
                    "Scan completed",
                    extra={
                        "context": {
                            "scan_id": str(scan_id),
                            "urls_crawled": scan.urls_crawled,
                            "requests_sent": scan.requests_sent,
                            "findings_count": len(findings),
                        }
                    },
                )

        except Exception as exc:
            logger.exception("Scan failed", extra={"context": {"scan_id": str(scan_id)}})
            await _mark_failed(session, scan, str(exc))


async def _mark_failed(session: AsyncSession, scan: Scan, error: str) -> None:
    scan.status = ScanStatus.FAILED
    scan.error = error[:2000]
    scan.finished_at = datetime.now(UTC)
    await session.commit()


async def _mark_cancelled(session: AsyncSession, scan: Scan) -> None:
    scan.status = ScanStatus.CANCELLED
    scan.finished_at = datetime.now(UTC)
    await session.commit()
