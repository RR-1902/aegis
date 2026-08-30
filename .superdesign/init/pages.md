# Pages

## / (current dashboard)

Entry: `dashboard/src/App.tsx`

Dependencies:

- `dashboard/src/components/Header.tsx`
- `dashboard/src/components/StatusBar.tsx`
  - `dashboard/src/types/api.ts`
  - `dashboard/src/utils/format.ts`
- `dashboard/src/components/SummaryPanel.tsx`
  - `dashboard/src/types/api.ts`
- `dashboard/src/components/EventFilters.tsx`
  - `dashboard/src/types/api.ts`
- `dashboard/src/components/EventsTable.tsx`
  - `dashboard/src/types/api.ts`
  - `dashboard/src/utils/format.ts`
- `dashboard/src/components/EventDetails.tsx`
  - `dashboard/src/types/api.ts`
  - `dashboard/src/utils/format.ts`
- `dashboard/src/api/events.ts`
  - `dashboard/src/api/client.ts`
  - `dashboard/src/types/api.ts`
- `dashboard/src/styles.css`

The render branch is a desktop two-column master/detail layout with events on the left and the selected event’s causal chain on the right.
