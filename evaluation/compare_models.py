"""
Evaluation Harness: compares risk model outputs on the same finding set.

This script demonstrates Section 30's research comparison by:
1. Creating synthetic findings (simulating scanner output)
2. Scoring them under Default, Conservative, and SeverityOnly models
3. Comparing rankings across models
4. Outputting a structured comparison report

Usage:
    cd backend
    python -m evaluation.compare_models
"""
from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Any

# Add backend directory to path for imports.
import os
_backend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
sys.path.insert(0, _backend_dir)

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # noqa: F401
from app.database.base import Base
from app.models.enums import ExposureLevel, HttpMethod, ScanStatus, Severity
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.risk.engine import RiskCalculator, RiskEngine
from app.risk.models import ConservativeRiskModel, DefaultRiskModel, SeverityOnlyRiskModel
from app.risk.prioritizer import Prioritizer


# Synthetic finding definitions representing typical scanner output.
SYNTHETIC_FINDINGS = [
    {
        "url": "http://testapp.com/login",
        "method": HttpMethod.POST,
        "parameter": "username",
        "vulnerability_type": "sql_injection",
        "title": "SQL Injection in login form",
        "description": "The username parameter is vulnerable to SQL injection via error-based technique.",
        "severity": Severity.CRITICAL,
        "confidence": 0.95,
        "exploitability": 0.9,
        "impact": 0.95,
        "exposure": ExposureLevel.PUBLIC,
        "detector_name": "sql_injection",
    },
    {
        "url": "http://testapp.com/search",
        "method": HttpMethod.GET,
        "parameter": "q",
        "vulnerability_type": "xss_reflected",
        "title": "Reflected XSS in search query",
        "description": "The search parameter reflects user input without sanitization.",
        "severity": Severity.HIGH,
        "confidence": 0.85,
        "exploitability": 0.7,
        "impact": 0.7,
        "exposure": ExposureLevel.PUBLIC,
        "detector_name": "xss_reflected",
    },
    {
        "url": "http://testapp.com/api/users",
        "method": HttpMethod.GET,
        "parameter": None,
        "vulnerability_type": "broken_access_control",
        "title": "User list accessible without authentication",
        "description": "The /api/users endpoint returns all user data without auth.",
        "severity": Severity.HIGH,
        "confidence": 0.6,
        "exploitability": 0.8,
        "impact": 0.85,
        "exposure": ExposureLevel.AUTHENTICATED,
        "detector_name": "access_control",
    },
    {
        "url": "http://testapp.com/debug",
        "method": HttpMethod.GET,
        "parameter": None,
        "vulnerability_type": "information_disclosure",
        "title": "Debug page exposed",
        "description": "A debug page with stack traces is publicly accessible.",
        "severity": Severity.MEDIUM,
        "confidence": 0.9,
        "exploitability": 0.3,
        "impact": 0.4,
        "exposure": ExposureLevel.PUBLIC,
        "detector_name": "information_disclosure",
    },
    {
        "url": "http://testapp.com/contact",
        "method": HttpMethod.POST,
        "parameter": "message",
        "vulnerability_type": "csrf",
        "title": "CSRF token missing on contact form",
        "description": "The contact form does not include an anti-CSRF token.",
        "severity": Severity.MEDIUM,
        "confidence": 0.35,
        "exploitability": 0.4,
        "impact": 0.3,
        "exposure": ExposureLevel.PUBLIC,
        "detector_name": "csrf",
    },
    {
        "url": "http://testapp.com/",
        "method": HttpMethod.GET,
        "parameter": None,
        "vulnerability_type": "security_headers",
        "title": "Missing Content-Security-Policy header",
        "description": "The response does not include a Content-Security-Policy header.",
        "severity": Severity.LOW,
        "confidence": 1.0,
        "exploitability": 0.1,
        "impact": 0.2,
        "exposure": ExposureLevel.PUBLIC,
        "detector_name": "security_headers",
    },
    {
        "url": "http://testapp.com/admin",
        "method": HttpMethod.GET,
        "parameter": None,
        "vulnerability_type": "broken_access_control",
        "title": "Admin panel accessible with low-priv user",
        "description": "The admin panel is accessible to non-admin users.",
        "severity": Severity.CRITICAL,
        "confidence": 0.5,
        "exploitability": 0.6,
        "impact": 0.9,
        "exposure": ExposureLevel.AUTHENTICATED,
        "detector_name": "access_control",
    },
    {
        "url": "http://testapp.com/upload",
        "method": HttpMethod.POST,
        "parameter": "file",
        "vulnerability_type": "xss_stored",
        "title": "Stored XSS via file upload name",
        "description": "The uploaded filename is rendered without sanitization.",
        "severity": Severity.HIGH,
        "confidence": 0.7,
        "exploitability": 0.6,
        "impact": 0.75,
        "exposure": ExposureLevel.PUBLIC,
        "detector_name": "xss_stored",
    },
]


async def run_evaluation():
    """Run the full model comparison evaluation."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    async with factory() as session:
        # Create a target and scan.
        target = Target(
            name="Evaluation Target",
            base_url="http://testapp.com",
            allowed_domains=[],
            scan_config={},
        )
        session.add(target)
        await session.flush()

        scan = Scan(
            target_id=target.id,
            status=ScanStatus.COMPLETED,
            config_snapshot={},
        )
        session.add(scan)
        await session.flush()

        # Create synthetic findings.
        findings = []
        for finding_data in SYNTHETIC_FINDINGS:
            finding = Finding(scan_id=scan.id, **finding_data)
            session.add(finding)
            findings.append(finding)
        await session.flush()

        print("=" * 70)
        print("EVALUATION: Risk Model Comparison (Section 30)")
        print("=" * 70)
        print(f"\nFindings: {len(findings)}")
        print(f"Models: DefaultRiskModel, ConservativeRiskModel, SeverityOnlyRiskModel")

        results: dict[str, list[dict[str, Any]]] = {}

        for model_name, model_cls in [
            ("Default", DefaultRiskModel),
            ("Conservative", ConservativeRiskModel),
            ("SeverityOnly", SeverityOnlyRiskModel),
        ]:
            model = model_cls()
            risk_engine = RiskEngine(session, model=model)

            # Score all findings.
            for finding in findings:
                await risk_engine.score_finding(finding)

            # Rank all findings.
            prioritizer = Prioritizer(session)
            prioritized = await prioritizer.rank_all(scan.id)

            results[model_name] = [
                {
                    "rank": p.rank,
                    "title": p.finding.title,
                    "severity": p.finding.severity.value,
                    "risk_score": p.finding.risk_score,
                    "risk_band": p.risk_band,
                    "explanation": p.explanation,
                }
                for p in prioritized
            ]

            print(f"\n{'-' * 70}")
            print(f"Model: {model_name}")
            print(f"{'-' * 70}")
            for item in results[model_name]:
                print(
                    f"  #{item['rank']:2d} | {item['risk_score']:5.1f} | "
                    f"{item['risk_band']:13s} | {item['severity']:13s} | "
                    f"{item['title']}"
                )

        # Compare rankings.
        print(f"\n{'=' * 70}")
        print("RANKING COMPARISON")
        print(f"{'=' * 70}")

        default_ranks = {r["title"]: r["rank"] for r in results["Default"]}
        conservative_ranks = {r["title"]: r["rank"] for r in results["Conservative"]}
        severity_ranks = {r["title"]: r["rank"] for r in results["SeverityOnly"]}

        print(f"\n{'Finding':<45} {'Default':>8} {'Conserv.':>8} {'SevOnly':>8}")
        print("-" * 70)
        for title in default_ranks:
            d = default_ranks[title]
            c = conservative_ranks.get(title, "-")
            s = severity_ranks.get(title, "-")
            print(f"{title:<45} {d:>8} {c:>8} {s:>8}")

        # Kendall's tau correlation (manual implementation).
        print(f"\n{'=' * 70}")
        print("KENDALL'S TAU CORRELATION")
        print(f"{'=' * 70}")

        def kendall_tau(ranks_a: dict, ranks_b: dict) -> float:
            common = set(ranks_a.keys()) & set(ranks_b.keys())
            n = len(common)
            if n < 2:
                return 0.0
            items = list(common)
            concordant = 0
            discordant = 0
            for i in range(n):
                for j in range(i + 1, n):
                    a_diff = ranks_a[items[i]] - ranks_a[items[j]]
                    b_diff = ranks_b[items[i]] - ranks_b[items[j]]
                    if a_diff * b_diff > 0:
                        concordant += 1
                    elif a_diff * b_diff < 0:
                        discordant += 1
            return (concordant - discordant) / (n * (n - 1) / 2)

        tau_dc = kendall_tau(default_ranks, conservative_ranks)
        tau_ds = kendall_tau(default_ranks, severity_ranks)
        tau_cs = kendall_tau(conservative_ranks, severity_ranks)

        print(f"  Default vs Conservative:  {tau_dc:+.3f}")
        print(f"  Default vs SeverityOnly:  {tau_ds:+.3f}")
        print(f"  Conservative vs SeverityOnly: {tau_cs:+.3f}")

        # Score distribution comparison.
        print(f"\n{'=' * 70}")
        print("SCORE DISTRIBUTION")
        print(f"{'=' * 70}")

        for model_name in results:
            scores = [r["risk_score"] for r in results[model_name]]
            avg = sum(scores) / len(scores)
            print(f"  {model_name:15s}: min={min(scores):.1f}, max={max(scores):.1f}, "
                  f"avg={avg:.1f}, spread={max(scores) - min(scores):.1f}")

        # Band changes between models.
        print(f"\n{'=' * 70}")
        print("BAND CHANGES: Default vs SeverityOnly")
        print(f"{'=' * 70}")

        default_bands = {r["title"]: r["risk_band"] for r in results["Default"]}
        severity_bands = {r["title"]: r["risk_band"] for r in results["SeverityOnly"]}

        changes = 0
        for title in default_bands:
            if default_bands[title] != severity_bands[title]:
                changes += 1
                print(f"  {title}: {default_bands[title]} -> {severity_bands[title]}")
        print(f"\n  Total band changes: {changes}/{len(default_bands)}")

        # Save full report as JSON.
        report = {
            "models": results,
            "correlations": {
                "default_vs_conservative": tau_dc,
                "default_vs_severity_only": tau_ds,
                "conservative_vs_severity_only": tau_cs,
            },
            "band_changes": changes,
            "total_findings": len(findings),
        }

        report_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "evaluation_report.json",
        )
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nFull report saved to: {report_path}")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run_evaluation())
