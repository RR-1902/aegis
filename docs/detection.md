# Detection in AEGIS

AEGIS currently implements a **stateless deterministic detection layer** with
this boundary:

```text
FeatureObservation -> DetectionEngine -> List[DetectionResult]
```

## Input boundary

Detection consumes immutable finalized `FeatureObservation` objects only.
It does **not** inspect:

- raw packets
- mutable `Flow` objects
- `FlowWindow` internals
- `FlowBuilder` internals

## Rule model

Each rule is stateless and evaluates one observation at a time:

```python
evaluate(observation: FeatureObservation) -> Optional[DetectionResult]
```

Initial supported rules:

- `PortScanRule`
- `SynFloodRule`

## DetectionResult

Each detection result is immutable and explainable. It contains:

- `rule_id`
- `rule_name`
- `severity`
- `flow_key`
- `window_start`
- `window_end`
- `evidence`
- `explanation`

Severity is rule-local and deterministic. It is **not** the same as any future
risk score.

## Threshold source of truth

Runtime deterministic rules read thresholds from `app/config/settings.py`.

For the thresholds currently used by detection, the authoritative runtime names
are:

- `settings.port_scan_threshold`
- `settings.port_scan_time_window`
- `settings.syn_rate_threshold`
- `settings.syn_incomplete_ratio`

`app/config/thresholds.py` still exists as a separate documented threshold set,
but it is not the runtime source of truth for the current stateless engine.

## Explainability

Each rule returns structured evidence containing:

- observation identity
- relevant feature values
- configured thresholds
- actual comparisons used for the decision

The human-readable explanation is generated from the same values.

## Detection identity and deduplication

The engine deduplicates detections in memory using:

```text
(rule_id, flow_key, window_start, window_end)
```

Evaluating the same observation twice will not produce duplicate effective
results.

## FlowKey strategy impact

Detection quality depends on observation identity strategy.

### PortScanRule

- `five_tuple`: port changes can split activity across multiple observations,
  reducing visibility of multi-port scans
- `three_tuple`: multiple destination ports can aggregate into one observation,
  which improves visibility for port-scan-style behavior
- `bidirectional`: identity is direction-independent, so evidence must be
  interpreted without assuming initiator/responder semantics

### SynFloodRule

Works from per-window SYN and incomplete-connection features and is less
sensitive to port aggregation than port-scan detection, but still operates only
on the provided observation scope.

## Safety boundary

The detection layer only classifies observations. It does not:

- score threats
- create incidents
- trigger policy
- execute response actions
- invoke shell/system commands
