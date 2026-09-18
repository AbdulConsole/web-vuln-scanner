from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

import app.models  # noqa: F401  (registers all models on Base.metadata)
from app.database.base import Base
from app.models.enums import (
    ExposureLevel,
    FindingStatus,
    HttpMethod,
    ParameterSource,
    ScanStatus,
    Severity,
)
from app.models.finding import Evidence, Finding, RiskScoreBreakdown
from app.models.scan import Scan
from app.models.target import Target

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


async def _make_target_and_scan(session, name="Test App"):
    target = Target(
        name=name,
        base_url="http://localhost:5000",
        allowed_domains=["localhost"],
        scan_config={},
    )
    session.add(target)
    await session.flush()

    scan = Scan(target_id=target.id, status=ScanStatus.QUEUED, config_snapshot={})
    session.add(scan)
    await session.flush()
    return target, scan


async def test_create_target_and_scan(session):
    target, scan = await _make_target_and_scan(session)
    await session.commit()

    assert scan.id is not None
    assert scan.target_id == target.id
    assert scan.status == ScanStatus.QUEUED
    assert scan.duration_seconds is None  # not started/finished yet


async def test_cascade_delete_target_removes_scans(session):
    target, scan = await _make_target_and_scan(session)
    await session.commit()
    scan_id = scan.id

    await session.delete(target)
    await session.commit()

    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    assert result.scalar_one_or_none() is None


async def test_url_form_parameter_relationships(session):
    from app.models.attack_surface import Form, Parameter, Url

    _, scan = await _make_target_and_scan(session)

    url = Url(scan_id=scan.id, url="http://localhost:5000/login", method=HttpMethod.GET)
    session.add(url)
    await session.flush()

    form = Form(
        url_id=url.id,
        action="/login",
        method=HttpMethod.POST,
        inputs=[{"name": "username", "type": "text"}],
    )
    param = Parameter(
        url_id=url.id, name="redirect", source=ParameterSource.QUERY, sample_value="/"
    )
    session.add_all([form, param])
    await session.commit()

    result = await session.execute(
        select(Url)
        .options(selectinload(Url.forms), selectinload(Url.parameters))
        .where(Url.id == url.id)
    )
    loaded = result.scalar_one()
    assert len(loaded.forms) == 1
    assert loaded.forms[0].inputs[0]["name"] == "username"
    assert len(loaded.parameters) == 1
    assert loaded.parameters[0].source == ParameterSource.QUERY


async def test_finding_with_evidence_and_risk_breakdown(session):
    _, scan = await _make_target_and_scan(session)

    finding = Finding(
        scan_id=scan.id,
        url="http://localhost:5000/login",
        method=HttpMethod.POST,
        parameter="username",
        vulnerability_type="sql_injection",
        title="Possible SQL Injection",
        description="Error-based indicator observed in response.",
        severity=Severity.HIGH,
        confidence=0.75,
        exploitability=0.6,
        impact=0.8,
        exposure=ExposureLevel.PUBLIC,
        detector_name="sqli_detector",
        status=FindingStatus.OPEN,
    )
    session.add(finding)
    await session.flush()

    evidence = Evidence(
        finding_id=finding.id,
        kind="response_diff",
        sanitized_payload={"note": "db error string observed"},
    )
    breakdown = RiskScoreBreakdown(
        finding_id=finding.id,
        factor_name="severity",
        raw_value=0.8,
        weight=0.3,
        contribution=24.0,
    )
    session.add_all([evidence, breakdown])
    await session.commit()

    result = await session.execute(
        select(Finding)
        .options(
            selectinload(Finding.evidence_items), selectinload(Finding.risk_breakdowns)
        )
        .where(Finding.id == finding.id)
    )
    loaded = result.scalar_one()
    assert len(loaded.evidence_items) == 1
    assert loaded.evidence_items[0].kind == "response_diff"
    assert len(loaded.risk_breakdowns) == 1
    assert loaded.risk_breakdowns[0].factor_name == "severity"


async def test_cascade_delete_finding_removes_evidence_and_breakdowns(session):
    _, scan = await _make_target_and_scan(session)

    finding = Finding(
        scan_id=scan.id,
        url="http://localhost/x",
        method=HttpMethod.GET,
        vulnerability_type="xss",
        title="Reflected XSS",
        description="Test marker reflected unencoded.",
        severity=Severity.MEDIUM,
        confidence=0.5,
        exploitability=0.5,
        impact=0.5,
        exposure=ExposureLevel.PUBLIC,
        detector_name="xss_detector",
    )
    session.add(finding)
    await session.flush()

    evidence = Evidence(
        finding_id=finding.id, kind="reflection", sanitized_payload={"note": "x"}
    )
    session.add(evidence)
    await session.commit()
    evidence_id = evidence.id

    await session.delete(finding)
    await session.commit()

    result = await session.execute(select(Evidence).where(Evidence.id == evidence_id))
    assert result.scalar_one_or_none() is None


async def test_confidence_check_constraint_rejects_out_of_range_value(session):
    _, scan = await _make_target_and_scan(session)

    bad_finding = Finding(
        scan_id=scan.id,
        url="http://localhost/x",
        method=HttpMethod.GET,
        vulnerability_type="xss",
        title="t",
        description="d",
        severity=Severity.LOW,
        confidence=1.5,  # invalid: must be within [0.0, 1.0]
        exploitability=0.1,
        impact=0.1,
        exposure=ExposureLevel.PUBLIC,
        detector_name="xss_detector",
    )
    session.add(bad_finding)
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_risk_score_check_constraint_rejects_out_of_range_value(session):
    _, scan = await _make_target_and_scan(session)

    bad_finding = Finding(
        scan_id=scan.id,
        url="http://localhost/x",
        method=HttpMethod.GET,
        vulnerability_type="xss",
        title="t",
        description="d",
        severity=Severity.LOW,
        confidence=0.5,
        exploitability=0.1,
        impact=0.1,
        exposure=ExposureLevel.PUBLIC,
        detector_name="xss_detector",
        risk_score=150.0,  # invalid: must be within [0.0, 100.0]
    )
    session.add(bad_finding)
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()
