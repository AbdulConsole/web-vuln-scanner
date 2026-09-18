# Risk Scoring Methodology

This is the project's core research contribution: turning a detected
vulnerability into an explainable, comparable 0–100 risk score, rather
than stopping at severity alone.

## The Formula

For a given finding, each of four factors is normalized to `[0.0, 1.0]`,
multiplied by a model-specific weight, and summed into a base score out
of 100. That base score is then scaled by a confidence multiplier:

```
base_score = (severity × w_severity
            + exploitability × w_exploitability
            + impact × w_impact
            + exposure × w_exposure) × 100

final_score = clamp(base_score × confidence_multiplier(confidence), 0, 100)
```

Weights are expected to sum to `1.0`, so a finding with every factor
maxed out and full detector confidence scores exactly 100 — this is
checked directly in `tests/unit/test_risk_calculator.py::test_default_model_max_everything_scores_exactly_100`.

## The Factors

| Factor | Source | Range | Meaning |
|---|---|---|---|
| Severity | `Finding.severity` enum, mapped via `risk/factors.py` | 0.1 (Informational) - 1.0 (Critical) | How technically serious the vulnerability class is, independent of this specific instance |
| Exploitability | Set per-finding by the detector | 0.0 - 1.0 | How difficult this specific instance is to exploit (a confirmed SQL error vs. a boolean-differential signal have different exploitability, even for the same vulnerability type) |
| Impact | Set per-finding by the detector | 0.0 - 1.0 | What could happen if exploited (data exposure, account takeover, etc.) |
| Exposure | `Finding.exposure` enum, mapped via `risk/factors.py` | 0.15 (Restricted) - 1.0 (Public) | How reachable the vulnerable component is |
| Confidence | Set per-finding by the detector | 0.0 - 1.0 | How certain the detector is -- not summed with the other four, but applied as a *multiplier* on the weighted base score |

Confidence is deliberately a multiplier, not a fifth summed term: a
"probable" finding (confidence 0.5) should have its entire score scaled
down, not just lose a small fixed amount -- a low-confidence Critical
finding and a low-confidence Informational finding should stay far apart
in score, which a multiplier preserves and a flat penalty would not.

## Score Bands

| Range | Band |
|---|---|
| 0-19 | Informational |
| 20-39 | Low |
| 40-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

See `app/risk/scoring.py::score_to_band()`.

## Worked Example

Severity=High (0.75), Exploitability=0.5, Impact=0.5, Exposure=Authenticated (0.6), Confidence=0.5, under `DefaultRiskModel`:

```
base = (0.75x0.30 + 0.5x0.25 + 0.5x0.25 + 0.6x0.20) x 100
     = (0.225 + 0.125 + 0.125 + 0.12) x 100 = 59.5

final = 59.5 x 0.5 = 29.75   ->  Low
```

The same finding under `ConservativeRiskModel` (different weights, and a
**squared** confidence curve):

```
base = (0.75x0.40 + 0.5x0.20 + 0.5x0.25 + 0.6x0.15) x 100
     = (0.30 + 0.10 + 0.125 + 0.09) x 100 = 61.5

final = 61.5 x (0.5^2) = 61.5 x 0.25 = 15.375   ->  Informational
```

Same evidence, same finding -- a 14-point score difference and a
different band, purely from the scoring strategy. This is exactly the
kind of comparison Section 30 asks the architecture to support.

## Extensibility: Swappable Models

`RiskModel` (`app/risk/scoring.py`) is an abstract interface: a `weights()`
method and an optional `confidence_multiplier()` override. Three concrete
models ship today:

- **`DefaultRiskModel`** -- the scanner's baseline (weights above).
- **`ConservativeRiskModel`** -- weights severity more heavily and squares
  the confidence curve, so unconfirmed findings are pushed down harder.
  Intended for environments where false-positive noise must be minimized.
- **`SeverityOnlyRiskModel`** -- ignores exploitability, impact, exposure,
  and confidence entirely, scoring purely by severity. This exists
  specifically as the baseline Section 30 asks for: running the *same*
  finding set through this model versus `DefaultRiskModel` is how the
  value of risk-based prioritization over severity-only prioritization
  gets demonstrated, without re-running any detector.

Adding a new model is one new file: subclass `RiskModel`, implement
`weights()`, register it wherever `RiskEngine` is constructed
(`RiskEngine(session, model=YourModel())`). Nothing else changes --
`RiskCalculator` handles normalization, clamping, and breakdown
construction identically for every model.

## Explainability

Every scoring run persists one `RiskScoreBreakdown` row per factor
(including a `confidence_adjustment` row), not just the final number.
`FactorContribution.contribution` values always sum exactly to the final
score -- enforced by construction and checked in
`test_breakdown_contributions_sum_to_final_score`. This is what the
Prioritization Engine (Milestone 10) reads to build its "ranked #1
because..." explanation, rather than reverse-engineering a reason from
the score alone.

Re-scoring a finding under a different model does **not** delete its
prior breakdown rows -- both scoring runs stay inspectable, which is what
makes an A/B comparison between models auditable after the fact rather
than just a number you have to trust.

## Mapping to the Original Spec's Vocabulary

The originating brief names four classes: `RiskFactor`, `RiskModel`,
`RiskCalculator`, `Prioritizer`. This codebase implements three of those
as directly-named classes (`RiskModel`, `RiskCalculator` in
`app/risk/engine.py`, `Prioritizer` arriving in Milestone 10). `RiskFactor`
is realized differently: severity and exposure are fixed, small
enumerations with no behavior beyond "produce a normalized value," so
`app/risk/factors.py`'s lookup functions plus the `RiskFactorInput`
dataclass serve that role without an unnecessary class hierarchy around
two lookup tables.

## Known Limitations

- Exploitability, impact, and confidence are currently set by each
  detector's own judgment at detection time (see Milestone 7), not
  computed by this engine. The risk engine's job is combining and
  explaining those inputs, not deriving them from scratch.
- Weights are hand-chosen based on standard vulnerability-management
  practice (severity and exploitability weighted most heavily), not
  empirically calibrated against a labeled dataset. Section 30's
  evaluation-support work (comparing models against real scan results)
  is the intended path to validating or adjusting these weights with
  actual data, rather than proceeding as if the current defaults are
  known-optimal.
