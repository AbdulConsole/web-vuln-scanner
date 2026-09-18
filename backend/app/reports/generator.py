"""
Report generation (Section 23).

Generates reports in JSON, HTML, and PDF formats for completed scans.
Reports are stored in the generated_reports/ directory and tracked in the
reports table.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.models.enums import ReportFormat
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import Scan
from app.risk.scoring import score_to_band

logger = get_logger(__name__)

REPORTS_DIR = Path("generated_reports")


def _ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


class ReportGenerator:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def generate(self, scan_id: uuid.UUID, format: str) -> Report:
        """Generate a report for a scan in the specified format."""
        report_format = ReportFormat(format)

        # Load scan with findings.
        result = await self.session.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = result.scalar_one_or_none()
        if scan is None:
            from app.core.exceptions import NotFoundError
            raise NotFoundError(f"Scan {scan_id} not found")

        # Load findings with breakdowns.
        findings_result = await self.session.execute(
            select(Finding)
            .options(selectinload(Finding.risk_breakdowns))
            .where(Finding.scan_id == scan_id)
            .where(Finding.risk_score.isnot(None))
            .order_by(Finding.priority_rank)
        )
        findings = list(findings_result.scalars().all())

        # Generate content.
        reports_dir = _ensure_reports_dir()
        filename = f"report_{scan_id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{format}"
        storage_path = str(reports_dir / filename)

        if report_format == ReportFormat.JSON:
            content = self._generate_json(scan, findings)
            with open(storage_path, "w", encoding="utf-8") as f:
                json.dump(content, f, indent=2, default=str)
        elif report_format == ReportFormat.HTML:
            content = self._generate_html(scan, findings)
            with open(storage_path, "w", encoding="utf-8") as f:
                f.write(content)
        elif report_format == ReportFormat.PDF:
            html_content = self._generate_html(scan, findings)
            # Write temp HTML for weasyprint.
            temp_html = str(reports_dir / f"temp_{scan_id}.html")
            with open(temp_html, "w", encoding="utf-8") as f:
                f.write(html_content)
            try:
                from weasyprint import HTML
                HTML(filename=temp_html).write_pdf(storage_path)
            except ImportError:
                logger.warning("weasyprint not installed, falling back to HTML report")
                os.rename(temp_html, storage_path.replace(".pdf", ".html"))
                report_format = ReportFormat.HTML
            finally:
                if os.path.exists(temp_html):
                    os.remove(temp_html)

        # Create report record.
        report = Report(
            scan_id=scan_id,
            format=report_format,
            storage_path=storage_path,
        )
        self.session.add(report)
        await self.session.flush()
        await self.session.commit()

        logger.info(
            "Report generated",
            extra={
                "context": {
                    "scan_id": str(scan_id),
                    "format": format,
                    "storage_path": storage_path,
                }
            },
        )
        return report

    def _generate_json(self, scan: Scan, findings: list[Finding]) -> dict:
        return {
            "scan_id": str(scan.id),
            "target_id": str(scan.target_id),
            "status": scan.status.value if hasattr(scan.status, "value") else scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "urls_crawled": scan.urls_crawled,
            "requests_sent": scan.requests_sent,
            "findings": [
                {
                    "id": str(f.id),
                    "url": f.url,
                    "method": f.method.value if hasattr(f.method, "value") else f.method,
                    "parameter": f.parameter,
                    "vulnerability_type": f.vulnerability_type,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                    "confidence": f.confidence,
                    "exploitability": f.exploitability,
                    "impact": f.impact,
                    "exposure": f.exposure.value if hasattr(f.exposure, "value") else f.exposure,
                    "risk_score": f.risk_score,
                    "risk_band": score_to_band(f.risk_score or 0),
                    "priority_rank": f.priority_rank,
                    "remediation": f.remediation,
                    "detector_name": f.detector_name,
                    "status": f.status.value if hasattr(f.status, "value") else f.status,
                }
                for f in findings
            ],
            "summary": {
                "total_findings": len(findings),
                "by_severity": self._count_by_severity(findings),
                "by_risk_band": self._count_by_risk_band(findings),
            },
        }

    def _generate_html(self, scan: Scan, findings: list[Finding]) -> str:
        summary = self._count_by_severity(findings)
        risk_summary = self._count_by_risk_band(findings)

        findings_html = ""
        for f in findings:
            severity_class = f.severity.value if hasattr(f.severity, "value") else f.severity
            risk_band = score_to_band(f.risk_score or 0)
            status_val = f.status.value if hasattr(f.status, "value") else f.status
            findings_html += f"""
            <tr>
                <td>{f.priority_rank or '-'}</td>
                <td><span class="badge badge-{severity_class}">{severity_class}</span></td>
                <td>{f.title}</td>
                <td>{f.url}</td>
                <td>{f.parameter or '-'}</td>
                <td>{f.risk_score:.1f if f.risk_score else '-'}</td>
                <td>{risk_band}</td>
                <td>{f.detector_name}</td>
                <td><span class="badge badge-{status_val}">{status_val}</span></td>
            </tr>"""

        scan_status = scan.status.value if hasattr(scan.status, "value") else scan.status
        started = scan.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.started_at else 'N/A'
        finished = scan.finished_at.strftime('%Y-%m-%d %H:%M:%S UTC') if scan.finished_at else 'N/A'

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {scan.id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .summary h2 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; }}
        .badge-critical {{ background: #d32f2f; }}
        .badge-high {{ background: #f57c00; }}
        .badge-medium {{ background: #fbc02d; color: #333; }}
        .badge-low {{ background: #388e3c; }}
        .badge-informational {{ background: #1976d2; }}
        .badge-open {{ background: #757575; }}
        .badge-confirmed {{ background: #d32f2f; }}
        .badge-false_positive {{ background: #9e9e9e; }}
        .badge-resolved {{ background: #388e3c; }}
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Scan ID:</strong> {scan.id}</p>
    <p><strong>Target ID:</strong> {scan.target_id}</p>
    <p><strong>Status:</strong> {scan_status}</p>
    <p><strong>Started:</strong> {started}</p>
    <p><strong>Finished:</strong> {finished}</p>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>URLs Crawled:</strong> {scan.urls_crawled}</p>
        <p><strong>Requests Sent:</strong> {scan.requests_sent}</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
        <h3>By Severity</h3>
        <ul>
            {"".join(f"<li>{k}: {v}</li>" for k, v in summary.items())}
        </ul>
        <h3>By Risk Band</h3>
        <ul>
            {"".join(f"<li>{k}: {v}</li>" for k, v in risk_summary.items())}
        </ul>
    </div>

    <h2>Findings</h2>
    <table>
        <thead>
            <tr>
                <th>Rank</th>
                <th>Severity</th>
                <th>Title</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Risk Score</th>
                <th>Risk Band</th>
                <th>Detector</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {findings_html}
        </tbody>
    </table>
</body>
</html>"""

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            severity = f.severity.value if hasattr(f.severity, "value") else f.severity
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _count_by_risk_band(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            band = score_to_band(f.risk_score or 0)
            counts[band] = counts.get(band, 0) + 1
        return counts
