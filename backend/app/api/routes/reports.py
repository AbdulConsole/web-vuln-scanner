"""
Report API routes.
"""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.exceptions import NotFoundError
from app.database.database import get_db
from app.models.report import Report
from app.schemas.report import ReportCreate, ReportList, ReportRead

router = APIRouter(tags=["reports"])

# Reports directory.
REPORTS_DIR = Path(get_settings().SECRET_KEY).parent / "generated_reports"


def _ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


@router.post("/scans/{scan_id}/reports", response_model=ReportRead, status_code=201)
async def create_report(
    scan_id: uuid.UUID,
    payload: ReportCreate,
    session: AsyncSession = Depends(get_db),
):
    """Generate a report for a scan."""
    from app.reports.generator import ReportGenerator
    generator = ReportGenerator(session)
    report = await generator.generate(scan_id, payload.format)
    return ReportRead.from_model(report)


@router.get("/scans/{scan_id}/reports", response_model=ReportList)
async def list_scan_reports(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
):
    result = await session.execute(
        select(Report).where(Report.scan_id == scan_id)
    )
    reports = result.scalars().all()
    return ReportList(
        items=[ReportRead.from_model(r) for r in reports],
        total=len(reports),
    )


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    session: AsyncSession = Depends(get_db),
):
    result = await session.execute(
        select(Report).where(Report.id == report_id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise NotFoundError(f"Report {report_id} not found")

    if not os.path.exists(report.storage_path):
        raise NotFoundError(f"Report file not found at {report.storage_path}")

    media_types = {
        "json": "application/json",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    return FileResponse(
        report.storage_path,
        media_type=media_types.get(report.format, "application/octet-stream"),
        filename=f"report_{report.scan_id}.{report.format}",
    )
