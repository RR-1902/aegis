import type { SecurityEvent } from '../types/api';
import { formatDateTime, formatFlowKey, formatShortId, titleCase } from '../utils/format';

type Props = {
  events: SecurityEvent[];
  selectedEventId: string | null;
  onSelect: (event: SecurityEvent) => void;
  loading: boolean;
  error: string | null;
  filtersApplied: boolean;
};

function badgeClass(value: string): string {
  return `badge badge-${value.toLowerCase()}`;
}

export default function EventsTable({ events, selectedEventId, onSelect, loading, error, filtersApplied }: Props) {
  if (loading) {
    return <section className="panel table-panel">Loading events...</section>;
  }

  if (error) {
    return <section className="panel table-panel error-message">{error}</section>;
  }

  if (events.length === 0) {
    return (
      <section className="panel table-panel empty-state">
        {filtersApplied ? 'No events match the selected filters.' : 'No security events recorded.'}
      </section>
    );
  }

  return (
    <section className="panel table-panel">
      <table>
        <thead>
          <tr>
            <th>Event ID</th>
            <th>Event Window</th>
            <th>Recorded</th>
            <th>Source / Destination</th>
            <th>Detection Type(s)</th>
            <th>Risk</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.event_id}
              className={selectedEventId === event.event_id ? 'selected' : ''}
              onClick={() => onSelect(event)}
              onKeyDown={(keyboardEvent) => {
                if (keyboardEvent.key === 'Enter' || keyboardEvent.key === ' ') {
                  keyboardEvent.preventDefault();
                  onSelect(event);
                }
              }}
              tabIndex={0}
              role="button"
              aria-pressed={selectedEventId === event.event_id}
            >
              <td className="mono" title={event.event_id}>{formatShortId(event.event_id, 20)}</td>
              <td className="mono">{formatDateTime(event.window_start)} → {formatDateTime(event.window_end)}</td>
              <td className="mono">{formatDateTime(event.recorded_at)}</td>
              <td className="mono">{formatFlowKey(event.flow_key)}</td>
              <td>{event.detections.map((detection) => detection.rule_name).join(', ')}</td>
              <td>
                <span className={badgeClass(event.risk.level)}>{titleCase(event.risk.level)}</span>
                <span className="risk-score">{event.risk.score}</span>
              </td>
              <td>
                <span className={badgeClass(event.lifecycle_status)}>{titleCase(event.lifecycle_status)}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
