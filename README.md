# Intelligent Web Application Vulnerability Scanner

**Design and Implementation of an Intelligent Web Application Vulnerability
Scanner Using Risk-Based Vulnerability Prioritization**

## ⚠️ Authorized Use Only

This tool is intended **exclusively** for:

- systems you own,
- systems you have explicit written authorization to test,
- localhost / controlled lab environments,
- intentionally vulnerable applications used for research and training.

Scanning systems without authorization is illegal in most jurisdictions.
The scanner includes technical safeguards (scope validation, SSRF/private-
network blocking) to reduce the risk of accidental out-of-scope scanning,
but these are not a substitute for obtaining proper authorization.

## Research Contribution

Most scanners stop at "vulnerability found." This project's contribution is
the layer *after* detection: a transparent, configurable **risk engine**
that combines severity, exploitability, impact, exposure, and detection
confidence into a single explainable risk score, and a **prioritization
engine** that answers *"which vulnerability should be fixed first, and
why?"* — with the reasoning shown, not just the ranking.

The risk model is pluggable (`RiskModel` interface) so different
weighting/scoring strategies can be compared experimentally, including
against a severity-only baseline.

## Architecture

```
Target → Scope Validation → Crawler → Attack Surface Model → Request Engine
  → Detection Engine → Findings → Evidence → Risk Engine → Prioritization
  → Remediation → Reports → Dashboard
```

See `docs/architecture.md` for the full breakdown.

## Project Status

This is being built incrementally in milestones (see `docs/architecture.md`
for the full list). **Currently implemented:**

- ✅ Milestone 1 — Project foundation: configuration, structured logging,
  exception handling, the core scope/SSRF safety guard, FastAPI app
  skeleton with a working `/api/health` endpoint, Docker/Compose setup,
  and an initial automated test suite.
- ✅ Milestone 2 — Database and models: normalized SQLAlchemy 2.0 async
  models for Target, Scan, Url/Form/Parameter, Finding, Evidence,
  RiskScoreBreakdown, Report, and a placeholder User table; a generic
  repository layer; and an Alembic migration environment configured for
  the async engine, with a hand-authored initial migration (see note
  below) that mirrors the models exactly.
- ✅ Milestone 3 — Target management: URL normalization/canonicalization
  and domain validation utilities (`app/core/url_utils.py`); Pydantic
  schemas for scan config, auth config, and target CRUD payloads with
  strict validation (`app/schemas/target.py`); and `TargetService`
  (`app/services/target_service.py`), which enforces target-name and
  base-URL uniqueness and runs every new/updated target through the
  `ScopeGuard` SSRF check before it can be persisted — a private-network
  target is rejected at creation time, not just at scan time.
- ✅ Milestone 4 — Crawler: a breadth-first crawler (`app/crawler/`) that
  discovers URLs, forms, and parameters as structured data (not raw HTML);
  enforces crawl depth, a URL cap, rate limiting, and bounded concurrency;
  respects robots.txt as a configurable policy; retries transient network
  errors with backoff; and re-validates scope on **every redirect hop**
  (not just the initial request), so a malicious or misconfigured redirect
  can't pivot the scanner outside its authorized target. Supports graceful
  cancellation via an `asyncio.Event`.
- ✅ Milestone 5 — Request engine: a single centralized `RequestEngine`
  (`app/scanner/request_engine.py`) through which **all** outbound HTTP
  flows — crawler and, from Milestone 6, every detector. Supports
  GET/POST/HEAD, query/form/JSON bodies, headers, cookies, per-hop
  redirect scope re-validation, bounded retries, a shared rate limiter and
  concurrency pool, response capture with metadata, and scan-wide request
  metrics. Authenticated scanning (basic / bearer / cookie) is supported
  via `app/scanner/auth.py`. **This milestone also paid off the Milestone 4
  consolidation debt**: `app/crawler/fetcher.py` has been deleted and the
  crawler now delegates to the shared engine.
- ✅ Milestone 6 — Detection framework: a plugin architecture for
  detectors (`app/detectors/`). `BaseDetector` defines the interface every
  detector implements; a global registry (`@register_detector`) means
  adding a new detector is a single new file — no other code changes.
  `DetectorManager` instantiates detectors from the registry, runs them
  concurrently against a `DetectionContext` (the crawler's attack surface
  + the shared `RequestEngine`), and **isolates per-detector failures** so
  one buggy or third-party detector can't abort detection for every other
  detector.
- ✅ Milestone 7 — Initial vulnerability detectors: seven detectors built
  on the Milestone 6 framework — SQL injection (error-based + boolean
  differential), reflected XSS, stored XSS, security headers, information
  disclosure (sensitive-file probing + debug-page detection), CSRF
  (heuristic token-field check), and broken access control (heuristic
  authenticated-vs-unauthenticated comparison). Every detector uses only
  safe, non-destructive techniques — no time-based SQLi, no actual script
  execution, no form submission without a token to "confirm" CSRF. Several
  detectors' real limitations (single-credential access-control testing,
  hosting-page-only stored-XSS verification, no time-based blind SQLi) are
  stated explicitly in code and docs rather than glossed over.
- ✅ Milestone 8 — Finding/Evidence system: `EvidenceCollector`
  (`app/evidence/collector.py`) translates in-memory `DetectorFinding`
  objects from Milestone 7 into persisted `Finding`/`Evidence` rows,
  running every piece of evidence through `sanitize_evidence()` first —
  redaction (via a shared `app/core/redaction.py`, now also used by
  structured logging) then size truncation, in that order, so a long
  *and* sensitive value can't end up half-redacted. Exact-duplicate
  findings within one scan are suppressed as a defensive backstop.
  `app/evidence/correlation.py` groups genuinely-distinct findings that
  likely share a root cause (e.g. the same SQLi pattern across
  `/item?id=1`, `?id=2`, `?id=3`) for reporting purposes, **without**
  altering what's actually persisted — every finding stays in the
  database for audit completeness.
- ✅ Milestone 9 — Risk Assessment Engine (the project's core research
  contribution): `RiskModel` (`app/risk/scoring.py`) is a pluggable
  weighting-strategy interface with three concrete implementations —
  `DefaultRiskModel`, `ConservativeRiskModel` (squares the confidence
  curve so unconfirmed findings are pushed down harder), and
  `SeverityOnlyRiskModel` (a deliberate baseline for the severity-only
  vs. risk-based comparison Section 30 asks for). `RiskCalculator`
  (`app/risk/engine.py`) is pure arithmetic — no database — combining
  severity/exploitability/impact/exposure by weight and applying
  confidence as a multiplier into a 0–100 score; `RiskEngine` persists the
  score plus a full per-factor `RiskScoreBreakdown` (including the
  confidence adjustment itself as its own row) so every score is
  explainable, not just a number. Full methodology, a worked numeric
  example comparing two models on identical input, and the mapping from
  the spec's `RiskFactor`/`RiskModel`/`RiskCalculator` vocabulary to this
  codebase's classes are in `docs/risk-model.md`.
- ✅ Milestone 10 — Prioritization engine: `Prioritizer` (`app/risk/prioritizer.py`)
  ranks scored findings by risk_score (with confidence and severity
  tiebreakers), assigns `priority_rank` on each Finding row, and generates
  human-readable explanations referencing the top contributing risk factors
  from `RiskScoreBreakdown` rows. Separated from scoring so risk models
  and ranking strategies can be swapped independently.
- ✅ Milestone 11 — REST API: 17 endpoints across targets, scans, findings,
  and reports. Background scan orchestration via `ScanRunner` wires the
  full pipeline (crawl → detect → persist → score → rank) as an asyncio
  task. Includes `ScanService`, `FindingService`, Pydantic schemas for all
  entities, and the `TargetService` exposed over HTTP.
- ✅ Milestone 12 — Frontend dashboard: React 18 + TypeScript + Tailwind CSS
  SPA with pages for Dashboard (overview), Targets (CRUD), Scans (start/monitor
  with status badges), Scan Detail (findings table with risk scores, report
  generation), and Findings (filterable table with detail modal showing evidence,
  risk breakdown, and status updates). Vite dev server proxies `/api` to backend.
- ✅ Milestone 13 — Report generation: `ReportGenerator` (`app/reports/generator.py`)
  produces JSON, HTML, and PDF reports. JSON includes full findings data and
  severity/risk-band summaries. HTML includes styled tables with severity badges.
  PDF uses weasyprint. Reports stored in `generated_reports/` and tracked in the
  `reports` table. Download via `/api/reports/{id}/download`.
- ✅ Milestone 14 — Evaluation harness: `evaluation/compare_models.py` creates
  synthetic findings, scores them under Default/Conservative/SeverityOnly models,
  compares rankings with Kendall's tau correlation, and outputs a structured
  comparison report. `evaluation/docker-compose.test.yml` spins up DVWA and
  Juice Shop as real test targets.

Everything else (frontend, reporting) is fully implemented — see the
milestone list above. The scanner now has a complete pipeline from
target creation through scanning, detection, risk scoring, prioritization,
reporting, and a React dashboard.

> **Note:** the crawler (Milestone 4) returns a `CrawlSummary` of plain
> dataclasses and does **not** write `Url`/`Form`/`Parameter` rows to the
> database — that translation happens in `ScanRunner` (Milestone 11) when
> scans run end-to-end. As of Milestone 5 it no longer carries its own
> HTTP client; all requests go through the shared `RequestEngine`.

## Running the Backend Locally

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env   # adjust as needed
uvicorn app.main:app --reload
```

Then visit `http://localhost:8000/api/health` and
`http://localhost:8000/docs` (interactive OpenAPI docs).

## Database Setup

For local development, tables can be created directly from the ORM models
(no migration history needed):

```python
import asyncio
from app.database.database import init_models
asyncio.run(init_models())
```

For anything beyond throwaway local dev, use Alembic instead so schema
changes are tracked and reversible:

```bash
cd backend
alembic upgrade head
```

> **Note on the initial migration:** `alembic/versions/0001_initial_schema.py`
> was hand-authored to mirror `app/models` exactly, rather than produced by
> `alembic revision --autogenerate` against a live database — the sandbox
> this project was authored in has no database or network access to run
> that command. Before relying on it in a real deployment, run
> `alembic check` (or autogenerate against an empty DB and diff the result)
> locally to confirm there's zero drift from the models.

## Running Tests

```bash
cd backend
pytest -v
```

> Note: in this sandboxed authoring environment, outbound network access is
> disabled, so the test suite could not be executed here to produce a live
> pass/fail report. The tests are ordinary `pytest` + `httpx.AsyncClient`
> tests against standard, current library APIs — run them locally with the
> command above to verify.

## Running with Docker

```bash
docker compose up --build
```

This starts a Postgres database and the backend API on port 8000.

## Configuration

All configuration is via environment variables — see `.env.example` for
the full list with descriptions. Notably:

- `ALLOW_PRIVATE_NETWORK_TARGETS` — must be explicitly set to `true` to scan
  localhost or private IP ranges (e.g. a co-located vulnerable test app).
  Defaults to `false`.
- `DATABASE_URL` — SQLite by default for development; set to a
  `postgresql+asyncpg://...` URL for production.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — full system architecture
- [`docs/risk-model.md`](docs/risk-model.md) — risk scoring methodology
- [`docs/detection-methodology.md`](docs/detection-methodology.md) — how each detector works
- [`docs/api.md`](docs/api.md) — API reference
- [`docs/testing.md`](docs/testing.md) — testing strategy
