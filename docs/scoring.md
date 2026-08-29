# Risk scoring in AEGIS

AEGIS currently implements a **stateless heuristic risk scoring** layer with
this boundary:

```text
List[DetectionResult] -> RiskScorer -> RiskScore
```

## Separation from detection

Detection answers:

- what suspicious behavior was observed

Scoring answers:

- how serious the combined detected evidence is

`RiskScorer` consumes `DetectionResult` objects only. It does not inspect:

- packets
- `Flow`
- `FlowWindow`
- `FlowBuilder`
- `FeatureObservation`

## Score semantics

The AEGIS risk score is a deterministic heuristic engineering score in the
range `0..100`.

It is:

- bounded and capped at 100
- additive across contributing detections for one observation identity
- explainable
- configurable

It is **not**:

- a probability
- a calibrated estimate of compromise
- an ML output

## DetectionSeverity vs RiskLevel

Detection severity is rule-local:

- `LOW`
- `MEDIUM`
- `HIGH`

Risk level is the combined score classification:

- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

A high-severity detection contributes more to the score, but detection severity
is not the same concept as the final risk level.

## Risk thresholds

Risk-level mapping uses the runtime settings in `app/config/settings.py`:

- `settings.threat_score_low = 29`
- `settings.threat_score_medium = 59`
- `settings.threat_score_high = 79`

Current mapping:

- `0..29` -> `LOW`
- `30..59` -> `MEDIUM`
- `60..79` -> `HIGH`
- `80..100` -> `CRITICAL`

## Scoring weights

Rule contributions are explicit runtime scoring configuration, separate from
detection thresholds.

Current heuristic defaults:

- `settings.score_port_scan_medium = 25`
- `settings.score_port_scan_high = 40`
- `settings.score_syn_flood_medium = 35`
- `settings.score_syn_flood_high = 55`

These are deterministic heuristic engineering defaults only. They are not
probabilities and should not be interpreted as calibrated risk values.

## Algorithm

For one observation identity:

1. start at `0`
2. sum rule-specific contributions from `(rule_id, severity)`
3. cap at `100`
4. map to `RiskLevel`
5. preserve contributing detections
6. generate a deterministic explanation from the actual contributions

## Identity and scope

The first scorer accepts detections from exactly one observation identity:

```text
(flow_key, window_start, window_end)
```

If detections from multiple identities are mixed, scoring fails clearly.

Overlapping sliding-window observations are scored independently. The scorer
does not aggregate across windows or maintain history.

## Explainability

`RiskScore` preserves the original `DetectionResult` objects and their evidence.
The score explanation additionally summarizes:

- final numeric score
- final `RiskLevel`
- contributing rules
- contributing severities
- contribution amounts

## Safety boundary

Risk scoring has no side effects. It does not:

- invoke policy
- execute response actions
- run shell/system commands
- call an LLM

## Future stateful scoring

Future phases may add stateful scoring across observations, sliding-window
correlation, incident accumulation, or decay over time. That is intentionally
out of scope for the current stateless scorer.
