# Layouts

## Root mount

- Source: `dashboard/src/main.tsx`
- Description: React StrictMode mount and global stylesheet.

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode><App /></React.StrictMode>,
);
```

## Application shell

- Source: `dashboard/src/App.tsx`
- Description: Single-page shell that concurrently loads health and events, refreshes them, and fetches selected-event details.
- Structure: header → health/status → summary → filters/event stream → selected detail.
- All data access is through `fetchHealth`, `fetchEvents`, and `fetchEvent` from `src/api/events.ts`.
