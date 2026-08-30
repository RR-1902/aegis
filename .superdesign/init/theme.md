# Theme

## Compact token summary

- Font: system sans stack; mono values use `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`.
- Current base: deep blue/graphite backgrounds (`#020617`, `#0f172a`), pale slate type (`#e2e8f0`, `#cbd5e1`), blue interactive accent.
- Severity colors: low blue, medium amber, high orange, critical red.
- Shape: panels use 12px rounding; tables and form controls are low-contrast bordered surfaces.
- Responsive thresholds: 1200px, 900px, 640px.

## Raw source inventory

The current global stylesheet is `dashboard/src/styles.css` (355 lines). It defines the root palette, panel, status, summary, table, detail, badge, and responsive selectors. The redesign may replace this stylesheet while preserving semantic state classes and contrast requirements.
