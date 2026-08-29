# Runtime pipeline in AEGIS

AEGIS now implements a first real end-to-end runtime orchestration layer:

```text
PacketCapture
    -> FlowBuilder
    -> finalized FeatureObservation
    -> DetectionEngine
    -> RiskScorer
    -> PolicyEngine
    -> ResponseEngine
    -> SecurityEvent
    -> SecurityEventStore
```

## Callback wiring

The runtime preserves the existing component boundaries:

- `PacketCapture.packet_callback -> FlowBuilder.add_packet`
- `FlowBuilder.feature_observation_callback -> AEGISPipeline._handle_feature_observation`

The pipeline does not inspect mutable flow/window internals for downstream
analytics.

## Observation boundary

Downstream security processing begins only when `FlowBuilder` emits a finalized
`FeatureObservation`.

This preserves the existing semantics:

- event-time window assignment
- fixed-window late-packet retention
- sliding-window overlap
- finalized-only canonical feature observations
- no mutation after observation emission

If an observation produces zero detections, AEGIS logs that outcome and does not
create or persist a `SecurityEvent`.

## Synchronous downstream processing

For the first runtime, observation handling is synchronous and runs in the
existing packet-processing thread created by `PacketCapture`.

This means:

- no new downstream queue is introduced
- detection/scoring/policy/response/persistence happen inline per finalized observation
- slow downstream processing can eventually increase pressure on the existing capture queue

That tradeoff is intentional for this first implementation.

## Failure isolation

Each finalized observation is processed independently.

Failures in:

- detection
- scoring
- policy
- response
- security-event construction
- persistence

are logged and abort only that observation's downstream processing. They do not
terminate packet capture or future observation processing.

## Lifecycle

`AEGISPipeline` exposes:

- `start()`
- `stop()`

Startup:

1. wire callbacks
2. start `PacketCapture`
3. begin accepting finalized observations

Shutdown:

1. stop accepting new downstream observation work
2. stop capture intake via existing `PacketCapture.stop()` lifecycle
3. mark the runtime stopped

## Current shutdown limitation

AEGIS does **not** currently implement an explicit flush/close-all API for all
remaining mutable windows during shutdown.

Therefore this runtime does **not** fabricate a final window flush and does not
claim to persist observations that were still mutable at shutdown time.

A future phase may add an explicit flush API.

## Entry point

The minimal runtime entry point is:

```bash
python -m app.main
```

It:

- configures basic logging
- constructs `AEGISPipeline`
- starts live capture
- waits until `Ctrl+C`
- stops the pipeline cleanly using existing lifecycle hooks

## Testability

`AEGISPipeline` supports lightweight constructor injection for:

- `PacketCapture`
- `FlowBuilder`
- `DetectionEngine`
- `RiskScorer`
- `PolicyEngine`
- `ResponseEngine`
- `SecurityEventStore`

This allows deterministic integration tests without:

- a real NIC
- admin privileges
- live capture traffic
- real firewall actions
- a real SQLite file if a fake store is injected

## Current scope

Implemented now:

- thin runtime orchestrator
- callback-based wiring
- synchronous finalized-observation processing
- security-event persistence for detected observations
- minimal runtime entry point

Still future work:

- explicit shutdown flush of mutable windows
- API/dashboard integration
- async scaling / secondary queues
- real response executor
- incident/history workflows
