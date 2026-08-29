import type { EventFilters as EventFiltersType } from '../types/api';

type Props = {
  filters: EventFiltersType;
  onChange: (filters: EventFiltersType) => void;
  onRefresh: () => void;
  loading: boolean;
};

export default function EventFilters({ filters, onChange, onRefresh, loading }: Props) {
  return (
    <section className="panel filters" aria-label="Event filters">
      <div className="filter-row">
        <label>
          <span>Risk level</span>
          <select
            value={filters.risk_level ?? 'all'}
            onChange={(event) => onChange({
              ...filters,
              risk_level: event.target.value === 'all' ? undefined : event.target.value as EventFiltersType['risk_level'],
            })}
          >
            <option value="all">All</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <label>
          <span>Lifecycle status</span>
          <select
            value={filters.lifecycle_status ?? 'all'}
            onChange={(event) => onChange({
              ...filters,
              lifecycle_status: event.target.value === 'all' ? undefined : event.target.value as EventFiltersType['lifecycle_status'],
            })}
          >
            <option value="all">All</option>
            <option value="no_action">No Action</option>
            <option value="simulated">Simulated</option>
            <option value="rejected">Rejected</option>
          </select>
        </label>
      </div>

      <button type="button" className="refresh-button" onClick={onRefresh} disabled={loading}>
        {loading ? 'Refreshing...' : 'Refresh'}
      </button>
    </section>
  );
}
