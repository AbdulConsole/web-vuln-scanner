from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

import app.models  # noqa: F401
from app.database.base import Base
from app.models.enums import ExposureLevel, HttpMethod, ScanStatus, Severity
from app.models.finding import Finding, RiskScoreBreakdown
from app.models.scan import Scan
from app.models.target import Target
from app.risk.engine import RiskEngine
from app.risk.models import DefaultRiskModel, SeverityOnlyRiskModel

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


async def test_score_finding_sets_risk_score_on_the_finding(session, scan_id):
    finding = await _make_finding(session, scan_id)
    risk_engine = RiskEngine(session)

    result = await risk_engine.score_finding(finding)
    await session.commit()

    assert finding.risk_score is not None
    assert finding.risk_score == pytest.approx(result.score, abs=0.01)


async def test_score_finding_persists_breakdown_rows(session, scan_id):
    finding = await _make_finding(session, scan_id)
    risk_engine = RiskEngine(session)

    await risk_engine.score_finding(finding)
    await session.commit()

    result = await session.execute(
        select(RiskScoreBreakdown).where(RiskScoreBreakdown.finding_id == finding.id)
    )
    rows = result.scalars().all()
    factor_names = {row.factor_name for row in rows}
    assert factor_names == {
        "severity", "exploitability", "impact", "exposure", "confidence_adjustment",
    }


async def test_score_all_scores_every_finding(session, scan_id):
    f1 = await _make_finding(session, scan_id, url="http://example.com/a")
    f2 = await _make_finding(session, scan_id, url="http://example.com/b", severity=Severity.LOW)
    risk_engine = RiskEngine(session)

    results = await risk_engine.score_all([f1, f2])
    await session.commit()

    assert len(results) == 2
    assert f1.risk_score is not None
    assert f2.risk_score is not None
    # High severity should score higher than Low severity, all else equal.
    assert f1.risk_score > f2.risk_score


async def test_default_model_used_when_none_specified(session, scan_id):
    risk_engine = RiskEngine(session)
    assert isinstance(risk_engine.model, DefaultRiskModel)


async def test_custom_model_can_be_injected(session, scan_id):
    finding = await _make_finding(session, scan_id)
    risk_engine = RiskEngine(session, model=SeverityOnlyRiskModel())

    await risk_engine.score_finding(finding)
    await session.commit()

    # Severity=HIGH -> 0.75 -> 75.0 regardless of the other factors, since
    # SeverityOnlyRiskModel ignores everything else.
    assert finding.risk_score == pytest.approx(75.0)


async def test_rescoring_a_finding_with_a_different_model_adds_new_breakdown_rows(
    session, scan_id
):
    """Re-running scoring under a different model (Section 30's research
    comparison) must not silently overwrite prior breakdown rows -- both
    scoring runs' history should be inspectable."""
    finding = await _make_finding(session, scan_id)

    await RiskEngine(session, model=DefaultRiskModel()).score_finding(finding)
    score_under_default = finding.risk_score

    await RiskEngine(session, model=SeverityOnlyRiskModel()).score_finding(finding)
    score_under_severity_only = finding.risk_score
    await session.commit()

    assert score_under_default != score_under_severity_only

    result = await session.execute(
        select(RiskScoreBreakdown).where(RiskScoreBreakdown.finding_id == finding.id)
    )
    rows = result.scalars().all()
    # 5 rows per scoring run (4 factors + confidence_adjustment) x 2 runs.
    assert len(rows) == 10


async def test_finding_loaded_fresh_reflects_persisted_risk_score(session, scan_id):
    finding = await _make_finding(session, scan_id)
    await RiskEngine(session).score_finding(finding)
    await session.commit()
    finding_id = finding.id

    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.risk_breakdowns))
        .where(Finding.id == finding_id)
    )
    loaded = result.scalar_one()
    assert loaded.risk_score is not None
    assert len(loaded.risk_breakdowns) == 5
