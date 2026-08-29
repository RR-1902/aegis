# Security events and persistence in AEGIS

AEGIS now implements a **durable SecurityEvent persistence layer** with this
boundary:

```text
FeatureObservation
    -> DetectionResult[]
    -> RiskScore
    -> ResponseDecision
    -> ResponseResult
    -> SecurityEvent
    -> SecurityEventStore
    -> SQLite
```

## One event per observation

AEGIS persists **one SecurityEvent per finalized observation identity**:

```text
(flow_key, window_start, window_end)
```

A single event may contain:

- zero or more `DetectionResult` objects
- one `RiskScore`
- one `ResponseDecision`
- one `ResponseResult`

AEGIS does **not** create one stored event per detection rule.

## Identity

The semantic identity of a security event is:

```text
(flow_key, window_start, window_end)
```

`event_id` is a deterministic hash derived from a canonical structured
serialization of:

- `FlowKey`
- `window_start`
- `window_end`

Semantically identical observations therefore produce the same `event_id`.

## Time semantics

- `window_start` / `window_end` are **event-time** observation bounds
- `recorded_at` is the **wall-clock persistence time**

AEGIS does not add a separate `observed_at` field in this phase because the
window bounds already capture the analytic event-time scope.

## Lifecycle status

Persisted lifecycle status is derived from `ResponseResult.status`:

- `ResponseStatus.NO_ACTION` -> `SecurityEventStatus.NO_ACTION`
- `ResponseStatus.SIMULATED` -> `SecurityEventStatus.SIMULATED`
- `ResponseStatus.REJECTED` -> `SecurityEventStatus.REJECTED`

`EXECUTED` and `FAILED` are currently rejected for persistence because AEGIS has
no real response executor yet.

## Evidence composition

`SecurityEvent` preserves the upstream nested models rather than flattening them
into one giant structure:

- `detections`
- `risk`
- `policy`
- `response`

This keeps the full explanation chain available for later dashboard/API/audit
consumption:

- why detection fired
- why the score was assigned
- why policy selected a response
- what the response layer actually did

## Serialization

Persistence uses deterministic structured serialization:

- `FlowKey` -> structured object, not `str(flow_key)`
- enums -> `.value`
- datetimes -> timezone-aware UTC ISO 8601
- nested models -> structured JSON-compatible dictionaries
- detection evidence -> preserved as structured JSON data

Unsupported non-JSON evidence is rejected clearly rather than silently
stringified.

## SQLite store

AEGIS currently provides a minimal SQLite-backed store with operations:

- `save(event) -> bool`
- `get(event_id) -> Optional[SecurityEvent]`
- `list_recent(limit=100) -> List[SecurityEvent]`

The current schema stores:

- indexed top-level event metadata
- deterministic `event_id`
- lifecycle/risk summary fields
- nested analytical content as JSON text

## Idempotent persistence

`save(event)` is idempotent by `event_id`:

- same `event_id` + equivalent content -> success/no-op
- same `event_id` + conflicting content -> rejected

AEGIS does not silently overwrite existing events.

## No raw packet persistence

This phase does **not** persist:

- raw packets
- packet payload bytes
- Scapy packet objects
- shell commands
- firewall command strings

Only analytical and audit metadata is stored.

## Current scope

Implemented now:

- immutable `SecurityEvent`
- deterministic event identity
- structured serialization/deserialization
- SQLite-backed persistence

Still future work:

- REST API exposure
- dashboard integration
- WebSocket/event streaming
- incident management
- historical lifecycle/event-sourcing model
