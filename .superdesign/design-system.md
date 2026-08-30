# AEGIS Web Experience

## Product and data boundaries

AEGIS is a read-only network intrusion detection and response interface. The web application is deliberately restricted to `GET /health`, `GET /events`, and `GET /events/{event_id}`. Decorative landing-page visuals may be abstract, but the dashboard must never invent telemetry, attacks, scores, IP addresses, lifecycle states, or control surfaces. There is no live firewall control and no SAFE_MODE display.

## Page system

- `/`: a cinematic product narrative with a sparse masthead, massive editorial typography, an abstract CSS/SVG topology, and five numbered observation-to-memory chapters.
- `/dashboard`: a disciplined security instrument: health/read-only header, one asymmetrical event summary, a dense event stream, and a dominant causal detail column.

## Visual language

- Base: near-black `#10110f`, graphite `#171815`, warm ivory `#f2efe7`, muted stone `#aca99f`.
- Accent: restrained oxidized chartreuse `#c8df67`; semantic severity uses muted clay/red/amber only where real event data calls for it.
- Typography: system sans only, with a weight-led editorial scale (12px labels, 15px body, 22px utility headings, 56–112px display). Use a monospaced system stack for IDs and flow values.
- Shape: 0–4px radius; paper-like divisions and hairline rules instead of rounded cards.
- Layout: generous vertical rhythm, wide asymmetric grids, strong alignment, layered rules, partial off-grid details, and intentionally dense data regions.
- Motion: subtle trace movement and staggered reveals on landing; quick opacity/transform state changes on dashboard. All animation is disabled or simplified with `prefers-reduced-motion`.

## Reference principles, not copied layouts

- Landing: editorial scale, controlled whitespace, restrained masthead, cinematic story progression, and an atmospheric abstract visual.
- Dashboard: clear content hierarchy, typographic information architecture, calm density, and sophisticated dark editorial treatment.
- Never copy brand assets, copy, visual identity, or layouts from external references.

## Required semantics

- CTA navigation must be ordinary anchor/client navigation: `ENTER AEGIS` and `OPEN DASHBOARD` go to `/dashboard`; dashboard offers return to `/`.
- Dashboard header only claims API/DATABASE state returned by `/health`.
- Event list and detail are real API responses. Empty, loading, unavailable, and not-found states remain explicit and truthful.
- Preserve keyboard selection, readable contrast, focus visibility, and responsive layouts for 1280px, 1024px, and 768px widths.
