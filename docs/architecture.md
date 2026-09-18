# Architecture

## Pipeline

```
Target
  → Scope Validation (ScopeGuard: domain scope + SSRF/private-network check)
  → Crawler (URL/form/parameter discovery, respects depth & robots.txt policy)
  → Attack Surface Model (structured URLs/forms/parameters, not raw HTML)
  → Request Engine (single point of HTTP I/O; rate-limited, bounded concurrency)
  → Detection Engine (plugin detectors run against the attack surface)
  → Findings (structured, with confidence + evidence)
  → Evidence Collector/Sanitizer (redacts secrets before persistence)
  → Risk Engine (RiskModel computes 0–100 risk score per finding)
  → Prioritization Engine (sorts + explains ranking)
  → Remediation Engine (attaches concrete fix guidance per finding)
  → Reports (JSON/HTML/PDF) + Dashboard (React)
```

## Module Responsibilities

| Module | Responsibility | Must NOT do |
|---|---|---|
| `core.security` | Scope + SSRF enforcement | Make HTTP requests itself |
| `crawler.*` | Discover attack surface | Send detector payloads |
| `scanner.request_engine` | All outbound HTTP | Contain detector-specific logic |
| `detectors.*` | Vulnerability-specific logic | Implement their own HTTP client |
| `risk.*` | Score + prioritize findings | Know about HTTP/crawling |
| `evidence.*` | Sanitize/store proof | Store raw secrets/tokens |
| `reports.*` | Render findings to output formats | Recompute risk scores |

This separation means: a new detector never touches the crawler, DB schema,
risk engine, or frontend. A new risk model never touches detectors.

## Milestones

1. Project foundation & configuration ✅
2. Database and models ✅
3. Target management ✅
4. Crawler ✅
5. Request engine ✅
6. Detection framework (plugin architecture) ✅
7. Initial vulnerability detectors (SQLi, XSS, headers, info disclosure, CSRF, access control) ✅
8. Finding/evidence system ✅
9. Risk assessment engine ✅
10. Prioritization engine ✅
11. REST API (17 endpoints + background scan orchestration) ✅
12. Frontend dashboard (React + Tailwind) ✅
13. Reporting (JSON/HTML/PDF) ✅
14. Testing and evaluation harness ✅
15. Docker/production hardening ✅

## Database Schema (Milestone 2)

```
targets ──1:N── scans ──1:N── urls ──1:N── forms
                   │              └──1:N── parameters
                   ├──1:N── findings ──1:N── evidence
                   │            └──1:N── risk_score_breakdowns
                   └──1:N── reports

users (standalone — not yet wired to any endpoint, see app/models/user.py)
```

Design notes:

- **UUID primary keys** via SQLAlchemy's cross-dialect `Uuid` type — native
  UUID on PostgreSQL, `CHAR(32)` on SQLite, so no model code changes when
  moving from dev to production.
- **Enums stored as VARCHAR, not native DB enums** (`native_enum=False`),
  so adding a new severity/status value is a Python-only change, never an
  `ALTER TYPE` migration.
- **CHECK constraints on `findings`** enforce `confidence`,
  `exploitability`, and `impact` ∈ [0.0, 1.0] and `risk_score` ∈ [0.0, 100.0]
  at the database level, not just in application code.
- **`risk_score_breakdowns`** stores one row per contributing factor per
  finding — this is what lets the Prioritization Engine (Milestone 10)
  explain *why* a finding ranked where it did, and lets later research
  experiments re-score the same findings under a different `RiskModel`
  without re-running detectors (Section 30).
- **`config_snapshot` on `scans`** freezes the target's scan configuration
  at scan-start time, so editing a target's defaults later doesn't
  retroactively change how a historical scan is interpreted.
- **`auth_config` on `targets` is plain JSON, not yet encrypted at rest** —
  flagged as a known limitation; do not store production credentials there
  until encryption lands.
- **`users` table is a placeholder** — no authentication endpoints, password
  hashing, or session handling exist yet. It's schema-only until that is
  built as its own milestone.

## Target Management (Milestone 3)

`TargetService` (`app/services/target_service.py`) is the domain layer
route handlers will call in Milestone 11 — it never touches FastAPI, so
the same validation applies to any future caller (CLI, background job).

Key behaviors:

- **URL normalization is centralized** in `app/core/url_utils.py`
  (lowercased scheme/host, default-port stripping, sorted query params,
  fragment removal). Target creation uses it for `base_url`; the crawler
  (Milestone 4) will reuse the same function for crawl-time deduplication,
  so "is this the same URL" is decided identically everywhere.
- **Duplicate-target prevention**: both target name and normalized
  `base_url` must be unique. Two targets pointing at the same
  normalized URL would make "which authorization applies here" ambiguous,
  so this is rejected outright rather than merged or warned about.
- **SSRF safety is enforced at target-creation time, not just scan time**:
  every new/updated target's `base_url` is resolved and checked against
  `ScopeGuard` before the row is written, using the same private-network
  blocklist described under Security Boundary below. This is a deliberate
  "fail early" choice — rejecting an unsafe target immediately is a better
  experience than accepting it and only failing when a scan later starts.
  The blocking DNS lookup this requires is dispatched via
  `asyncio.to_thread` so it doesn't stall the event loop.
- **`TargetRead` never serializes `auth_config` back out** — only a
  `has_auth_config` boolean. This is a direct consequence of the
  known limitation that `auth_config` is stored unencrypted (see the
  Database Schema section above): since we can't guarantee it's safe at
  rest yet, the API-facing schema is built so it can never leak the raw
  value even if a route handler forgets to redact it.

## Crawler (Milestone 4)

Breadth-first crawl, implemented across five small modules so each piece is
independently testable:

| Module | Role |
|---|---|
| `crawler/models.py` | Plain dataclasses for discovered surface (no ORM coupling) |
| `crawler/url_manager.py` | Frontier queue: dedup, depth cap, URL cap, scope pre-filter |
| `crawler/robots.py` | robots.txt as a configurable policy |
| `crawler/parser.py` | Link / form / parameter extraction from HTML |
| `crawler/crawler.py` | BFS orchestration and aggregation |

Design decisions worth calling out:

- **Two-stage scope checking, deliberately.** Cheap domain-scope filtering
  happens at *enqueue* time in `UrlManager` (so the frontier doesn't fill
  with off-site links), while the authoritative check —
  `ScopeGuard.validate()`, including DNS resolution and the private-network
  blocklist — runs at *fetch* time in `Fetcher`. The enqueue-time filter is
  an optimization; it is explicitly **not** the security boundary.
- **Redirects are followed manually** (`follow_redirects=False`) so scope
  can be re-validated on every hop — now implemented in the Request Engine.
  Letting httpx auto-follow would allow a 302 to an out-of-scope or
  private-network host to be fetched before any check ran. Directly tested in
  `tests/unit/test_request_engine.py::test_rejects_redirect_to_out_of_scope_domain`.
- **Forms default to GET when no method attribute is present**, matching the
  HTML spec and real browser behaviour, rather than assuming POST — the
  detectors need a form's *actual* method to test it correctly.
- **Crawler dataclasses are not ORM models.** The crawler has zero database
  dependency, which is why its tests need no DB fixture. Translation into
  `Url`/`Form`/`Parameter` rows is a separate concern.

Known limitations, stated plainly:

- The response-size cap bounds what is *retained*, not what is *downloaded* —
  httpx reads the full body first. Streaming with a hard download cap is a
  follow-up hardening item.
- No JavaScript execution: client-rendered routes and DOM-injected forms
  won't be discovered. A headless-browser crawl mode is out of scope for
  this project.

## Request Engine (Milestone 5)

`app/scanner/request_engine.py` is the single point of outbound HTTP for
the entire scanner. Nothing else constructs an httpx client.

Why centralize rather than let each component own its client:

1. **Security** — scope + SSRF validation runs here on every request and
   every redirect hop, so no detector can bypass it, even by accident.
2. **Politeness** — the rate limiter and concurrency semaphore are
   per-scan, not per-component. Five detectors each independently pacing
   at "5 req/s" would put 25 req/s on the target.
3. **Metrics** — one `RequestMetrics` counter backs the scan-progress
   reporting Section 18 requires.

Interface shape: detectors build a declarative `RequestSpec` (url, method,
params, data, headers, cookies) and receive an `HttpResponse` carrying
status, lowercased headers, decoded text, timing, redirect chain, byte
count, truncation flag, and any error. Failures are returned on the
response's `error` field rather than raised, so one unreachable URL can
never abort an entire scan.

Supporting pieces:

- `app/scanner/rate_limiter.py` — minimum-interval limiter, deliberately
  **not** a token bucket. A token bucket permits bursts after idle periods,
  which is exactly the behaviour that stresses a target under test.
  Extracted as its own module so pacing is unit-tested against an injected
  fake clock with no real sleeping.
- `app/scanner/auth.py` — converts a target's stored `auth_config` into
  default headers/cookies for authenticated scanning (basic / bearer /
  cookie). Kept separate so the engine knows nothing about the Target model.

**Consolidation note:** this milestone deleted `app/crawler/fetcher.py`,
the duplicate HTTP implementation Milestone 4 introduced because this
engine did not yet exist. That debt was flagged at the time and is now
resolved — the crawler accepts an injected engine (normal case, so the
whole scan shares one) or builds its own for standalone runs.

Carried-forward limitation: the response-size cap still bounds what is
*retained*, not what is *downloaded* — httpx buffers the full body before
truncation. A true download cap needs streaming responses.

## Detection Framework (Milestone 6)

`app/detectors/` is the plugin architecture Section 9 asks for. No
concrete detectors exist yet (that's Milestone 7) — this milestone is the
scaffolding they'll all plug into.

- **`detectors/base.py`** — `BaseDetector` (the interface every detector
  implements: `name`, `vulnerability_type`, `description`,
  `default_severity` as class attributes, plus `detect()` and
  `generate_evidence()`), `DetectionContext` (bundles the crawler's
  attack surface with the shared `RequestEngine`), and `DetectorFinding` /
  `DetectorEvidence` — plain dataclasses, not ORM rows, so detectors need
  no database to test. `DetectorFinding` enforces the same `[0.0, 1.0]`
  bound on confidence/exploitability/impact as the DB CHECK constraints
  from Milestone 2, but at construction time — a detector bug fails where
  it was introduced, not three layers away at insert time.
- **`detectors/manager.py`** — the registry and orchestrator.
  `@register_detector` is a class decorator that adds a detector to a
  global registry keyed by name, raising immediately (at import time) on a
  missing or duplicate name — a fail-loud choice, since a silent
  registration collision would otherwise surface only as "one of your
  detectors mysteriously didn't run" at scan time. `discover_builtin_detectors()`
  imports every sibling module in the package so those decorators execute;
  this is the literal mechanism behind "adding a new detector requires
  minimal changes" — it's one new file, zero edits anywhere else.

**The one property this milestone exists to guarantee:** a detector that
raises an exception cannot take down the rest of detection.
`DetectorManager.run_all()` runs every detector concurrently (bounded by a
semaphore) and catches per-detector exceptions individually, returning
them as error strings alongside whatever findings the *other* detectors
produced. Directly tested in
`tests/unit/test_detector_manager.py::test_run_all_isolates_a_failing_detector`.

## Initial Vulnerability Detectors (Milestone 7)

Seven detectors, all built on the Milestone 6 framework, all using only
safe/non-destructive techniques per Section 1:

| Detector | Technique | Confirmed vs. probable |
|---|---|---|
| `sqli.py` | Single-quote error triggering; boolean-based (`OR '1'='1'` vs `AND '1'='2'`) differential response-size comparison | Confirmed = matched DB error signature. Probable = >5% response-size delta between TRUE/FALSE conditions |
| `xss.py` (`ReflectedXssDetector`) | Unique canary payload (`"'><vsxss...`) injected per-parameter; static string/encoding analysis of the response, never executed | Confirmed = payload reflected byte-for-byte. Probable = canary survived but wasn't cleanly HTML-escaped either |
| `xss.py` (`StoredXssDetector`) | Same canary submitted to POST forms, then the hosting page is re-fetched to check persistence | Same confirmed/probable split as reflected |
| `security_headers.py` | Single fetch of the target's base URL; checks CSP/X-Frame-Options/HSTS/X-Content-Type-Options/Referrer-Policy/Permissions-Policy presence, plus weak-CSP-directive detection | Header absence is directly observable — confidence 1.0 |
| `information_disclosure.py` | Active probing of ~11 curated sensitive paths (`.git/config`, `.env`, `phpinfo.php`, ...) requiring **both** 200 status and a content signature match; re-checks only 5xx crawled URLs for debug-page signatures | Both checks are evidence-gated, not status-code-alone |
| `csrf.py` | Field-name heuristic (`csrf`, `_token`, `authenticity_token`, ...) on state-changing forms | Heuristic only — see limitation below |
| `access_control.py` | Authenticated vs. unauthenticated GET comparison on URLs whose path heuristically looks sensitive (`admin`, `settings`, ...) | Heuristic only — see limitation below |

**Shared infrastructure**, to avoid seven detectors each reinventing the
same request-building logic:

- `detectors/signatures.py` — every detector's pattern list (SQL errors,
  debug-page markers, sensitive paths, CSRF token hints, security-header
  metadata) lives here, so a single review/update touches one file.
- `detectors/probing.py` — `collect_param_targets()` builds the
  deduplicated set of (url, method, parameter) combinations worth testing
  from the crawl's discovered query parameters and form fields, used
  identically by `sqli.py` and `xss.py`. It strips a URL's existing query
  string before re-attaching parameters explicitly (so a probe value
  *replaces* the original rather than appending alongside it), and never
  probes password fields.

**Limitations stated explicitly, not glossed over** (Section 37):

- **No time-based blind SQLi.** `SLEEP()`/`WAITFOR` techniques work by
  making the target do extra work — applied across every discovered
  parameter, that conflicts with Section 19's "remain stable and
  respectful of target resources." Only error-based and boolean-based
  detection are implemented.
- **CSRF can only report "Not detected" or "Potential issue," never
  "Confirmed."** Confirming would require submitting a form without a
  token to see if the server accepts it — an actual state-changing
  action performed purely to test a hypothesis, which conflicts with
  Section 1's non-destructive-by-default requirement.
- **Access control testing is single-identity only.** True
  privilege-escalation testing needs two distinct authenticated accounts;
  `Target`/`AuthConfig` (Milestone 3) holds exactly one credential set.
  `AccessControlDetector` returns no findings at all when
  `context.unauthenticated_engine` isn't supplied, rather than guessing.
  Multi-identity support is a schema change, not something worked around
  here.
- **Stored XSS only checks the form's own hosting page for persistence**,
  not other pages the stored value might also render on (e.g. a separate
  "view all comments" page).
- Submitting to a POST form to test stored XSS is an inherent,
  intentional state change (it creates a real record with a harmless
  canary value) — this is unavoidable for stored-XSS testing and matches
  how any real DAST tool works, but is worth the operator knowing before
  scanning a target where every submission matters.

## Finding/Evidence System (Milestone 8)

This is the layer where the detector/crawler world (plain dataclasses, no
database) meets the ORM world (Milestone 2's Finding/Evidence tables).

- **`app/core/redaction.py`** (new, shared) — the sensitive-key
  substring list and `redact()` function used by *both* structured
  logging (`app/core/logging.py`, refactored in this milestone to use it)
  and evidence sanitization. Centralizing this means the log redaction
  filter and the evidence sanitizer can never quietly disagree about what
  counts as a secret.
- **`app/evidence/sanitizer.py`** — `sanitize_evidence()` redacts first,
  then truncates long string values. That order is deliberate: redacting
  *after* truncation could cut a long secret in half and leave the
  visible half exposed.
- **`app/evidence/collector.py`** — `EvidenceCollector.persist_all()` is
  what a future scan orchestrator (Milestone 11) calls after
  `DetectorManager.run_all()`. It also does **exact-duplicate
  suppression**: two `DetectorFinding`s with an identical
  `(vulnerability_type, url, parameter, detector_name)` tuple collapse to
  one persisted row. This is a defensive backstop, not the primary
  dedup mechanism — Milestone 7's `collect_param_targets()` already
  prevents the pipeline from generating true duplicates in the first
  place; this just makes a hypothetical future detector's bug harmless
  instead of something that silently inflates a scan's finding count.
- **`app/evidence/correlation.py`** — a distinct, non-destructive concern
  from the above: `correlate_findings()` groups already-persisted,
  *genuinely different* findings that likely share a root cause (same
  detector + vulnerability type + URL path, differing only in query
  string — e.g. `/item?id=1` and `/item?id=2`). Nothing about this
  changes what's stored; it only affects how a report or dashboard might
  choose to present "1 issue, 3 occurrences" instead of 3 unrelated-
  looking rows. Every Finding row persisted by the collector remains in
  the database individually, for audit completeness.

Section 17's "optional manual confirmation" got a small, deliberately
minimal foothold here too: `FindingRepository.update_status()` lets a
finding's status change (e.g. to Confirmed or False Positive), with no
workflow rules enforced at this layer — a status *state machine* (can a
Resolved finding go back to Open?) is treated as an API/service-layer
concern for whoever exposes this over HTTP in Milestone 11, not something
to guess at here.

## Risk Assessment Engine (Milestone 9)

The project's core research contribution. Full methodology (formula,
worked example, factor definitions) lives in `docs/risk-model.md` --
summarized here in terms of how the code is organized.

`app/risk/`:

- **`factors.py`** — normalizes categorical `Severity`/`ExposureLevel`
  enums into `[0,1]` values via fixed lookup tables.
- **`scoring.py`** — the `RiskModel` abstract interface (a `weights()`
  method + optional `confidence_multiplier()` override), plus
  `FactorContribution`/`RiskScoreResult` and `score_to_band()`.
- **`models/`** — three concrete `RiskModel`s (`DefaultRiskModel`,
  `ConservativeRiskModel`, `SeverityOnlyRiskModel`), each swappable
  without touching scoring or persistence code.
- **`engine.py`** — `RiskCalculator` (pure arithmetic, no database — takes
  a `RiskFactorInput`, returns a `RiskScoreResult`) and `RiskEngine`
  (persists `risk_score` onto a `Finding` row plus one
  `RiskScoreBreakdown` row per factor, including the confidence
  adjustment itself as an explicit row).

**Deliberately excludes ranking.** `RiskEngine` scores findings; it does
not compare them to each other or assign `priority_rank`. That cross-
finding comparison, and the "ranked #1 because..." explanation, is
`app/risk/prioritizer.py` — Milestone 10. Keeping these separate means a
risk *model* can be swapped without touching ranking logic, and a ranking
*strategy* can be swapped without touching scoring arithmetic.

**Why `SeverityOnlyRiskModel` exists as a real, shipped model** rather
than a hypothetical: Section 30 explicitly asks for the ability to compare
severity-only prioritization against risk-based prioritization on the
same finding set, to demonstrate the value of the risk-based approach.
Having a concrete, usable severity-only baseline makes that comparison
something you can actually run (`RiskEngine(session, model=SeverityOnlyRiskModel())`
against the same findings already scored under `DefaultRiskModel`), not
just an architectural claim.

**Re-scoring history is preserved, not overwritten.** Running a second
`RiskEngine` pass with a different model over the same findings adds new
`RiskScoreBreakdown` rows rather than replacing the old ones (only the
Finding's single current `risk_score` field gets overwritten, since a
finding only has one *current* score at a time — but every scoring run's
breakdown stays in the table). This is what makes a model-comparison
experiment auditable after the fact.

## Security Boundary

`ScopeGuard` (in `core/security.py`) is the single choke point every
outbound request must pass through. It enforces:

1. **Domain scope** — the target host must match the target's configured
   base domain or an explicitly allowed additional domain (proper suffix
   matching, not substring matching, to avoid lookalike-domain bypasses).
2. **Network safety** — resolved IPs are checked against a blocklist of
   loopback, RFC1918 private ranges, link-local, and the common cloud
   metadata endpoint (`169.254.169.254`), unless lab mode is explicitly
   enabled via `ALLOW_PRIVATE_NETWORK_TARGETS`.

The Request Engine (Milestone 5) will call `ScopeGuard.validate()` before
every request, including redirect targets, so a malicious or misconfigured
redirect cannot be used to pivot the scanner outside its authorized scope.
