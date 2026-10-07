import type { SecurityEvent } from '../../types/api';
import { LEVELS } from '../../lib/engine';
import { humanize } from '../../lib/format';

const OUTCOMES = ['no_action', 'simulated', 'rejected'];

function countBy(events: SecurityEvent[], read: (event: SecurityEvent) => string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const event of events) {
    const key = read(event).toLowerCase();
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

/** One bar of risk levels across every loaded event, with outcome counts beside it. */
export default function Distribution({ events }: { events: SecurityEvent[] }) {
  const levels = countBy(events, (event) => event.risk.level);
  const outcomes = countBy(events, (event) => event.lifecycle_status);
  const total = events.length;

  return (
    <div className="distribution">
      <p className="distribution__total">
        <span className="distribution__count">{total}</span>
        {total === 1 ? 'event' : 'events'}
      </p>
      <div className="distribution__body">
        <div className="distribution__bar" aria-hidden="true">
          {LEVELS.map((level) => {
            const count = levels.get(level) ?? 0;
            return count > 0 ? (
              <span key={level} data-level={level} style={{ flexGrow: count }} />
            ) : null;
          })}
          {total === 0 && <span className="distribution__empty" />}
        </div>
        <dl className="distribution__legend">
          {LEVELS.map((level) => (
            <div key={level} data-level={level}>
              <dt>{humanize(level)}</dt>
              <dd>{levels.get(level) ?? 0}</dd>
            </div>
          ))}
        </dl>
        <dl className="distribution__legend distribution__legend--outcomes">
          {OUTCOMES.map((outcome) => (
            <div key={outcome} data-outcome={outcome}>
              <dt>{humanize(outcome)}</dt>
              <dd>{outcomes.get(outcome) ?? 0}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}
