# AEGIS Web Dashboard

The AEGIS dashboard is a single-page React + Vite + TypeScript interface for
monitoring persisted `SecurityEvent` records through the read-only REST API.

## Stack

- React
- Vite
- TypeScript
- plain CSS
- Vitest + React Testing Library

## API dependency

The dashboard consumes only:

- `GET /health`
- `GET /events`
- `GET /events/{event_id}`

It does not access Python modules, SQLite, packet capture, or pipeline
internals directly.

## Environment

Create a `.env` file in `dashboard/` from `.env.example`:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## Run locally

```bash
cd dashboard
npm install
npm run dev
```

Run tests:

```bash
npm run test
```

Build production bundle:

```bash
npm run build
```

## Dashboard screens

The dashboard contains one primary view with:

- AEGIS branding
- read-only status label
- API/database health
- last refresh time
- event summary cards
- filter controls
- recent events table
- event details panel

## No-mock-data principle

Production dashboard code never fabricates security events, counts, or attack
metadata. If the backend returns no persisted events, the UI truthfully shows:

`No security events recorded.`

## Demo flow

1. Open the dashboard
2. Show API/database health
3. Show recent security events
4. Apply a filter
5. Select an event
6. Walk through Detection -> Risk -> Policy -> Response
7. Show the event ID and persisted evidence
