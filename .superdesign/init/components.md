# Components

The dashboard has no third-party component library; shared UI is plain React plus CSS.

## Header

- Source: `dashboard/src/components/Header.tsx`
- Description: Product header with read-only status.

```tsx
export default function Header() {
  return (
    <header className="panel header">
      <div>
        <p className="eyebrow">AEGIS</p>
        <h1>Network Intrusion Detection Dashboard</h1>
        <p className="subtitle">Response outcomes shown from persisted AEGIS events.</p>
      </div>
      <div className="readonly-badge" aria-label="Read-only dashboard">READ-ONLY</div>
    </header>
  );
}
```

## EventFilters

- Source: `dashboard/src/components/EventFilters.tsx`
- Description: The only dashboard controls: two local API filters and refresh.
- Key props: `filters`, `onChange`, `onRefresh`, `loading`.

```tsx
export default function EventFilters({ filters, onChange, onRefresh, loading }: Props) {
  return <section className="panel filters" aria-label="Event filters">{/* risk and lifecycle selects, refresh button */}</section>;
}
```

## EventsTable

- Source: `dashboard/src/components/EventsTable.tsx`
- Description: Keyboard-selectable API event stream with loading, error, and empty branches.
- Key props: `events`, `selectedEventId`, `onSelect`, `loading`, `error`, `filtersApplied`.

```tsx
export default function EventsTable({ events, selectedEventId, onSelect, loading, error, filtersApplied }: Props) {
  if (loading) return <section className="panel table-panel">Loading events...</section>;
  if (error) return <section className="panel table-panel error-message">{error}</section>;
  if (events.length === 0) return <section className="panel table-panel empty-state">{filtersApplied ? 'No events match the selected filters.' : 'No security events recorded.'}</section>;
  return <section className="panel table-panel"><table>{/* selectable event rows */}</table></section>;
}
```

## EventDetails

- Source: `dashboard/src/components/EventDetails.tsx`
- Description: API-backed selected-event causality detail: detection, risk, policy, response.
- Key props: `event`, `loading`, `error`.

```tsx
export default function EventDetails({ event, loading, error }: Props) {
  if (loading) return <aside className="panel details-panel">Loading event details...</aside>;
  if (error) return <aside className="panel details-panel error-message">{error}</aside>;
  if (!event) return <aside className="panel details-panel empty-state">Select an event to inspect its security analysis.</aside>;
  return <aside className="panel details-panel">{/* identity plus Detection → Risk → Policy → Response */}</aside>;
}
```

## StatusBar and SummaryPanel

- Sources: `dashboard/src/components/StatusBar.tsx`, `dashboard/src/components/SummaryPanel.tsx`
- Description: API/database health and event-derived aggregate counts. Neither stores or invents data.
