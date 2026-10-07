# AEGIS REST API

AEGIS exposes a small REST API for persisted `SecurityEvent` records. Event
endpoints are read-only. The one write endpoint, `POST /simulations`, never
accepts event data: the client names a scenario and the server runs synthetic
packets through the real pipeline, which decides what to store.

## Scope

Implemented endpoints:

- `GET /health`
- `GET /events`
- `GET /events/{event_id}`
- `GET /simulations`
- `POST /simulations`

The API does not:

- control packet capture
- access mutable flows or windows
- execute responses
- modify policy
- accept, update, or delete event data from clients
- expose raw packets or payloads

## Data source

The API reads only from `SecurityEventStore`, using the existing
`SQLiteSecurityEventStore` implementation in production.

## Endpoints

### `GET /health`

Returns `200` when the API process is alive and SQLite is reachable.
Returns `503` if the event store cannot be read.

Example response:

```json
{
  "status": "ok",
  "app_name": "AEGIS",
  "app_version": "0.1.0",
  "database": "ok"
}
```

### `GET /events`

Returns recent persisted security events in descending `recorded_at` order.

Query parameters:

- `limit` - integer, default `50`, min `1`, max `200`
- `risk_level` - optional: `low`, `medium`, `high`, `critical`
- `lifecycle_status` - optional: `no_action`, `simulated`, `rejected`

Example response:

```json
{
  "items": [
    {
      "event_id": "security-event:...",
      "flow_key": {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.10",
        "protocol": "TCP",
        "src_port": null,
        "dst_port": null
      },
      "window_start": "2024-01-01T00:00:00+00:00",
      "window_end": "2024-01-01T00:00:05+00:00",
      "recorded_at": "2024-01-01T00:00:06+00:00",
      "detections": [],
      "risk": {},
      "policy": {},
      "response": {},
      "lifecycle_status": "simulated"
    }
  ],
  "count": 1,
  "limit": 50
}
```

### `GET /events/{event_id}`

Returns one persisted `SecurityEvent` by deterministic ID, or `404` if not
found.

### `GET /simulations`

Lists the attack scenarios and whether simulations are enabled
(`ALLOW_SIMULATIONS`, default `true`).

### `POST /simulations`

Body: `{"scenario": "syn_flood" | "port_scan" | "fast_scan" | "slow_scan" | "benign"}`.

Builds the scenario's packets in memory (`app/simulation/`), runs them through
the flow builder, rules, scorer, policy engine, response engine and event store,
and returns `201` with the events the pipeline stored. Source addresses come
from RFC 5737 documentation ranges, so simulated events are always
distinguishable from captured traffic.

```json
{
  "scenario": { "id": "fast_scan", "name": "Fast scan", "summary": "...", "flow_key_strategy": "three_tuple", "target": "10.0.0.4" },
  "source_ip": "203.0.113.137",
  "packets": 24,
  "stored": 1,
  "events": [{ "event_id": "security-event:...", "risk": { "score": 95, "level": "critical" } }]
}
```

Errors: `404 unknown_scenario`, `403 simulations_disabled`,
`429 too_many_requests` (one run per second per process), `503 storage_unavailable`.

## Error handling

The API returns safe structured error responses and does not expose stack
traces.

Typical error codes:

- `404` - event not found
- `422` - invalid query parameter
- `503` - storage unavailable
- `500` - malformed persisted record

## CORS

CORS allows any origin for `GET` and `POST`, so the dashboard hosted on Vercel
can reach the API hosted on Render. `tests/test_api.py::TestCors` expects an
origin allowlist instead; those three tests fail until the two are reconciled.
