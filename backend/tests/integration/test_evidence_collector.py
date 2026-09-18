from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

import app.models  # noqa: F401
from app.database.base import Base
from app.detectors.base import DetectorEvidence, DetectorFinding
from app.evidence.collector import EvidenceCollector
from app.models.enums import ExposureLevel, HttpMethod, ScanStatus, Severity
from app.models.finding import Evidence, Finding
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


def _make_detector_finding(
    url="http://example.com/x",
    parameter="id",
    vulnerability_type="sql_injection",
    detector_name="sql_injection",
    with_sensitive_evidence=False,
) -> DetectorFinding:
    evidence_payload = {"parameter": parameter, "payload": "1'"}
    if with_sensitive_evidence:
        evidence_payload["session_cookie"] = "secret-session-value"

    return DetectorFinding(
        url=url,
        method=HttpMethod.GET,
        vulnerability_type=vulnerability_type,
        title="Test finding",
        description="A test finding",
        severity=Severity.HIGH,
        confidence=0.9,
        exploitability=0.7,
        impact=0.8,
        exposure=ExposureLevel.PUBLIC,
        detector_name=detector_name,
        parameter=parameter,
        evidence=[DetectorEvidence(kind="test_evidence", payload=evidence_payload)],
    )


async def test_persist_finding_creates_finding_and_evidence_rows(session, scan_id):
    collector = EvidenceCollector(session)
    detector_finding = _make_detector_finding()

    finding = await collector.persist_finding(scan_id, detector_finding)
    await session.commit()

    assert finding.id is not None
    assert finding.scan_id == scan_id
    assert finding.vulnerability_type == "sql_injection"
    assert finding.risk_score is None  # not yet scored -- Milestone 9's job

    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.evidence_items))
        .where(Finding.id == finding.id)
    )
    loaded = result.scalar_one()
    assert len(loaded.evidence_items) == 1
    assert loaded.evidence_items[0].kind == "test_evidence"


async def test_persist_finding_sanitizes_evidence_before_storage(session, scan_id):
    collector = EvidenceCollector(session)
    detector_finding = _make_detector_finding(with_sensitive_evidence=True)

    finding = await collector.persist_finding(scan_id, detector_finding)
    await session.commit()

    result = await session.execute(select(Evidence).where(Evidence.finding_id == finding.id))
    evidence_row = result.scalar_one()
    assert evidence_row.sanitized_payload["session_cookie"] == "***REDACTED***"
    assert evidence_row.sanitized_payload["payload"] == "1'"


async def test_persist_all_persists_multiple_distinct_findings(session, scan_id):
    collector = EvidenceCollector(session)
    findings = [
        _make_detector_finding(url="http://example.com/a", parameter="id"),
        _make_detector_finding(url="http://example.com/b", parameter="id"),
    ]

    persisted = await collector.persist_all(scan_id, findings)
    await session.commit()

    assert len(persisted) == 2
    result = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    assert len(result.scalars().all()) == 2


async def test_persist_all_suppresses_exact_duplicates(session, scan_id):
    collector = EvidenceCollector(session)
    findings = [
        _make_detector_finding(url="http://example.com/a", parameter="id"),
        _make_detector_finding(url="http://example.com/a", parameter="id"),  # exact duplicate
        _make_detector_finding(url="http://example.com/a", parameter="name"),  # different param
    ]

    persisted = await collector.persist_all(scan_id, findings)
    await session.commit()

    assert len(persisted) == 2  # the exact duplicate was suppressed
    result = await session.execute(select(Finding).where(Finding.scan_id == scan_id))
    assert len(result.scalars().all()) == 2


async def test_persist_all_with_empty_list_persists_nothing(session, scan_id):
    collector = EvidenceCollector(session)
    persisted = await collector.persist_all(scan_id, [])
    assert persisted == []


async def test_finding_without_evidence_persists_with_no_evidence_rows(session, scan_id):
    collector = EvidenceCollector(session)
    finding_no_evidence = DetectorFinding(
        url="http://example.com/headers",
        method=HttpMethod.GET,
        vulnerability_type="security_misconfiguration",
        title="Missing header",
        description="d",
        severity=Severity.LOW,
        confidence=1.0,
        exploitability=0.2,
        impact=0.3,
        exposure=ExposureLevel.PUBLIC,
        detector_name="security_headers",
    )

    finding = await collector.persist_finding(scan_id, finding_no_evidence)
    await session.commit()

    result = await session.execute(select(Evidence).where(Evidence.finding_id == finding.id))
    assert result.scalars().all() == []
