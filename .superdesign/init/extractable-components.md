# Extractable components

## AppHeader

- Source: `dashboard/src/components/Header.tsx`
- Category: layout
- Description: AEGIS identity and read-only indicator.
- Extractable props: title, dashboardHref, homeHref.
- Hardcoded: product name and read-only semantics.

## EventFilterBar

- Source: `dashboard/src/components/EventFilters.tsx`
- Category: basic
- Description: Read-only risk/lifecycle API filter controls and refresh action.
- Extractable props: riskLevel, lifecycleStatus, refreshing.
- Hardcoded: filter labels and option sets.

## EventStream

- Source: `dashboard/src/components/EventsTable.tsx`
- Category: basic
- Description: Selectable security-event list/table.
- Extractable props: selectedEventId, loading, error, emptyLabel.
- Hardcoded: semantic column ordering and row keyboard behavior.
