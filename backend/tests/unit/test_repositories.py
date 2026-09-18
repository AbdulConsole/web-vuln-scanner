from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # noqa: F401
from app.database.base import Base
from app.database.repositories.finding_repository import FindingRepository
from app.database.repositories.scan_repository import ScanRepository
from app.database.repositories.target_repository import TargetRepository
from app.models.enums import ExposureLevel, HttpMethod, ScanStatus, Severity
from app.models.finding import Finding
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


async def test_target_repository_get_by_name(session):
    repo = TargetRepository(session)
    target = Target(
        name="Acme Test App",
        base_url="http://localhost:8080",
        allowed_domains=[],
        scan_config={},
    )
    await repo.add(target)
    await repo.commit()

    found = await repo.get_by_name("Acme Test App")
    assert found is not None
    assert found.id == target.id

    missing = await repo.get_by_name("Does Not Exist")
    assert missing is None


async def test_scan_repository_list_by_target_and_status(session):
    target_repo = TargetRepository(session)
    scan_repo = ScanRepository(session)

    target = await target_repo.add(
        Target(name="T", base_url="http://x", allowed_domains=[], scan_config={})
    )
    await session.flush()

    scan1 = await scan_repo.add(
        Scan(target_id=target.id, status=ScanStatus.COMPLETED, config_snapshot={})
    )
    scan2 = await scan_repo.add(
        Scan(target_id=target.id, status=ScanStatus.RUNNING, config_snapshot={})
    )
    await scan_repo.commit()

    by_target = await scan_repo.list_by_target(target.id)
    assert {s.id for s in by_target} == {scan1.id, scan2.id}

    running = await scan_repo.list_by_status(ScanStatus.RUNNING)
    assert [s.id for s in running] == [scan2.id]


async def test_finding_repository_priority_ordering_nulls_last(session):
    target_repo = TargetRepository(session)
    scan_repo = ScanRepository(session)
    finding_repo = FindingRepository(session)

    target = await target_repo.add(
        Target(name="T", base_url="http://x", allowed_domains=[], scan_config={})
    )
    await session.flush()
    scan = await scan_repo.add(
        Scan(target_id=target.id, status=ScanStatus.RUNNING, config_snapshot={})
    )
    await session.flush()

    def make_finding(priority_rank, vuln_type="xss"):
        return Finding(
            scan_id=scan.id,
            url="http://x/y",
            method=HttpMethod.GET,
            vulnerability_type=vuln_type,
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            confidence=0.5,
            exploitability=0.5,
            impact=0.5,
            exposure=ExposureLevel.PUBLIC,
            detector_name="detector",
            priority_rank=priority_rank,
        )

    unranked = await finding_repo.add(make_finding(None, "unranked"))
    second = await finding_repo.add(make_finding(2, "second"))
    first = await finding_repo.add(make_finding(1, "first"))
    await finding_repo.commit()

    ordered = await finding_repo.list_by_scan(scan.id, order_by_priority=True)
    ordered_ids = [f.id for f in ordered]

    assert ordered_ids[0] == first.id
    assert ordered_ids[1] == second.id
    assert ordered_ids[-1] == unranked.id  # NULL priority sorts last, not first


async def test_finding_repository_list_by_severity(session):
    target_repo = TargetRepository(session)
    scan_repo = ScanRepository(session)
    finding_repo = FindingRepository(session)

    target = await target_repo.add(
        Target(name="T", base_url="http://x", allowed_domains=[], scan_config={})
    )
    await session.flush()
    scan = await scan_repo.add(
        Scan(target_id=target.id, status=ScanStatus.RUNNING, config_snapshot={})
    )
    await session.flush()

    high = Finding(
        scan_id=scan.id,
        url="http://x/y",
        method=HttpMethod.GET,
        vulnerability_type="sqli",
        title="t",
        description="d",
        severity=Severity.HIGH,
        confidence=0.9,
        exploitability=0.9,
        impact=0.9,
        exposure=ExposureLevel.PUBLIC,
        detector_name="detector",
    )
    low = Finding(
        scan_id=scan.id,
        url="http://x/z",
        method=HttpMethod.GET,
        vulnerability_type="header",
        title="t",
        description="d",
        severity=Severity.LOW,
        confidence=0.3,
        exploitability=0.1,
        impact=0.1,
        exposure=ExposureLevel.PUBLIC,
        detector_name="detector",
    )
    await finding_repo.add(high)
    await finding_repo.add(low)
    await finding_repo.commit()

    high_only = await finding_repo.list_by_severity(scan.id, Severity.HIGH)
    assert [f.id for f in high_only] == [high.id]
