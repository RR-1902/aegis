# AEGIS Web Interface

The web interface in `dashboard/` is a React, TypeScript and Vite single-page site with two pages:

- **Overview** (`/`): what AEGIS is, a scroll-driven walk through one real attack, the detection
  rules, a rule lab, attack simulations, a glossary of every term, the architecture and the scope.
- **Event ledger** (`#/ledger`): the stored security events, filters, attack simulations and an
  inspector that shows each event's full decision chain.

Design decisions, tokens and motion rules are in `dashboard/DESIGN.md`.

## Stack

- React 18 and TypeScript
- Vite
- GSAP with ScrollTrigger, and Lenis for smooth scrolling
- Self-hosted fonts: Hubot Sans, Mona Sans and Geist Mono (Fontsource)
- Plain CSS in `src/styles/`
- Vitest and React Testing Library

## API dependency

The interface calls only:

- `GET /health`
- `GET /events?limit=200`
- `GET /events/{event_id}`
- `GET /simulations` and `POST /simulations`

It never reads Python modules, SQLite or capture internals directly. If the connected API predates
`/simulations`, the simulation panel says so and the rest of the site keeps working.

## Environment

Create `dashboard/.env` from `.env.example`:

```bash
VITE_API_BASE_URL=http://127.0.0.1:8000
```

## Run locally

```bash
cd dashboard
npm install
npm run dev        # development server
npm run test       # 30 Vitest tests
npm run build      # production bundle in dist/
npm run preview    # serve the production bundle
```

## What each part shows

| Part | Data source |
| --- | --- |
| Hero instrument and packet stream | Decorative, labelled as illustrative in code; no numbers are claimed |
| "Follow one attack" story | The inputs of the `fast_scan` scenario; the final stage shows the real stored event ID |
| Rules and levels | Constants mirrored from `app/config/settings.py` |
| Rule lab | `src/lib/engine.ts`, a browser copy of the rules, scorer, policy and response engines, tested against the Python numbers |
| Simulate an attack | `POST /simulations`, which runs the real Python pipeline on synthetic packets |
| Latest event and ledger | `GET /events` |

## No invented data

The interface never fabricates events, counts or measurements. Every score and decision on screen is
either read from the API or computed by the same rules the backend uses. Events whose source is an
RFC 5737 documentation address (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are tagged
"Synthetic traffic", because only simulations use those addresses.

## Accessibility and motion

- Every glossary term on the page is keyboard focusable and shows its definition on focus.
- Filters and the selected event live in the URL, so any view can be linked.
- With `prefers-reduced-motion`, Lenis, pinning and all animation are switched off and the story
  stacks into a plain list.
- Only `transform` and `opacity` animate. Looping animations pause when off screen.

## Demo flow

1. Open the overview and scroll through "Follow one attack through AEGIS".
2. Try the rule lab: move the SYN rate past 10 and watch the verdict change.
3. Run the "Fast scan" simulation and watch the latest event update.
4. Open the console, select the new event and walk through window, detection, risk, policy and response.
5. Copy the event ID and show it is the SHA-256 of the flow key and window.
