# AEGIS REST API

AEGIS exposes a minimal read-only REST API for persisted `SecurityEvent`
records. The API is intentionally limited to dashboard-safe retrieval of stored
security events.

## Scope

Implemented endpoints:

- `GET /health`
- `GET /events`
- `GET /events/{event_id}`

The API does not:

- control packet capture
- access mutable flows or windows
- execute responses
- modify policy
- create, update, or delete events
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

## Error handling

The API returns safe structured error responses and does not expose stack
traces.

Typical error codes:

- `404` - event not found
- `422` - invalid query parameter
- `503` - storage unavailable
- `500` - malformed persisted record

## CORS

CORS is not enabled yet. A future dashboard integration can add an explicit
origin allowlist when needed.
