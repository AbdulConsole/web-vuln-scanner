from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

import app.models  # noqa: F401
from app.database.base import Base
from app.models.enums import ExposureLevel, HttpMethod, ScanStatus, Severity
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.risk.engine import RiskEngine
from app.risk.prioritizer import Prioritizer

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


@pytest.fixture
async def scan_id(session):
    target = Target(
        name="Test Target", base_url="http://example.com", allowed_domains=[], scan_config={}
    )
    session.add(target)
    await session.flush()
    scan = Scan(target_id=target.id, status=ScanStatus.RUNNING, config_snapshot={})
    session.add(scan)
    await session.flush()
    return scan.id


async def _make_finding(session, scan_id, **overrides) -> Finding:
    defaults = dict(
        scan_id=scan_id,
        url="http://example.com/item",
        method=HttpMethod.GET,
        vulnerability_type="sql_injection",
        title="Test finding",
        description="d",
        severity=Severity.HIGH,
        confidence=0.9,
        exploitability=0.7,
        impact=0.8,
        exposure=ExposureLevel.PUBLIC,
        detector_name="sql_injection",
    )
    defaults.update(overrides)
    finding = Finding(**defaults)
    session.add(finding)
    await session.flush()
    return finding


async def test_rank_all_assigns_sequential_ranks(session, scan_id):
    f1 = await _make_finding(session, scan_id, url="http://example.com/a", severity=Severity.HIGH)
    f2 = await _make_finding(session, scan_id, url="http://example.com/b", severity=Severity.LOW)
    f3 = await _make_finding(session, scan_id, url="http://example.com/c", severity=Severity.CRITICAL)

    await RiskEngine(session).score_all([f1, f2, f3])
    prioritized = await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    ranks = [p.rank for p in prioritized]
    assert ranks == [1, 2, 3]
    assert len(prioritized) == 3


async def test_rank_all_orders_by_risk_score_desc(session, scan_id):
    f_high = await _make_finding(session, scan_id, url="http://example.com/high", severity=Severity.CRITICAL)
    f_low = await _make_finding(session, scan_id, url="http://example.com/low", severity=Severity.LOW)

    await RiskEngine(session).score_all([f_high, f_low])
    prioritized = await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    assert prioritized[0].finding.id == f_high.id
    assert prioritized[1].finding.id == f_low.id
    assert prioritized[0].finding.risk_score >= prioritized[1].finding.risk_score


async def test_rank_all_persists_priority_rank_on_findings(session, scan_id):
    f1 = await _make_finding(session, scan_id, url="http://example.com/a", severity=Severity.HIGH)
    f2 = await _make_finding(session, scan_id, url="http://example.com/b", severity=Severity.LOW)

    await RiskEngine(session).score_all([f1, f2])
    await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    result = await session.execute(select(Finding).where(Finding.id == f1.id))
    loaded = result.scalar_one()
    assert loaded.priority_rank == 1

    result = await session.execute(select(Finding).where(Finding.id == f2.id))
    loaded = result.scalar_one()
    assert loaded.priority_rank == 2


async def test_rank_all_returns_empty_for_no_scored_findings(session, scan_id):
    prioritized = await Prioritizer(session).rank_all(scan_id)
    assert prioritized == []


async def test_rank_all_includes_explanation(session, scan_id):
    f1 = await _make_finding(session, scan_id, url="http://example.com/a")
    await RiskEngine(session).score_all([f1])
    prioritized = await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    assert len(prioritized) == 1
    assert prioritized[0].rank == 1
    assert "Ranked #1" in prioritized[0].explanation
    assert "risk score" in prioritized[0].explanation


async def test_rank_all_includes_risk_band(session, scan_id):
    f1 = await _make_finding(session, scan_id, url="http://example.com/a")
    await RiskEngine(session).score_all([f1])
    prioritized = await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    assert prioritized[0].risk_band in ("informational", "low", "medium", "high", "critical")


async def test_rank_all_breaks_tie_by_confidence(session, scan_id):
    f1 = await _make_finding(
        session, scan_id, url="http://example.com/a",
        severity=Severity.HIGH, confidence=0.9,
    )
    f2 = await _make_finding(
        session, scan_id, url="http://example.com/b",
        severity=Severity.HIGH, confidence=0.5,
    )

    await RiskEngine(session).score_all([f1, f2])
    prioritized = await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    # Higher confidence should rank first when severity and other factors are equal.
    assert prioritized[0].finding.id == f1.id
    assert prioritized[0].finding.confidence > prioritized[1].finding.confidence


async def test_rank_all_only_includes_scored_findings(session, scan_id):
    f_scored = await _make_finding(session, scan_id, url="http://example.com/scored")
    f_unscored = await _make_finding(session, scan_id, url="http://example.com/unscored")

    await RiskEngine(session).score_all([f_scored])
    # f_unscored has risk_score=NULL — should be excluded.
    prioritized = await Prioritizer(session).rank_all(scan_id)
    await session.commit()

    assert len(prioritized) == 1
    assert prioritized[0].finding.id == f_scored.id
