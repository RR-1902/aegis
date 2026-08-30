import type { SecurityEvent } from '../types/api';

type Props = {
  events: SecurityEvent[];
};

export default function SummaryPanel({ events }: Props) {
  const counts = {
    total: events.length,
    critical: events.filter((event) => event.risk.level === 'critical').length,
    high: events.filter((event) => event.risk.level === 'high').length,
    medium: events.filter((event) => event.risk.level === 'medium').length,
    noAction: events.filter((event) => event.lifecycle_status === 'no_action').length,
    simulated: events.filter((event) => event.lifecycle_status === 'simulated').length,
    rejected: events.filter((event) => event.lifecycle_status === 'rejected').length,
  };

  const cards = [
    ['Total Events', counts.total.toString()],
    ['Critical', counts.critical.toString()],
    ['High', counts.high.toString()],
    ['Medium', counts.medium.toString()],
    ['No Action', counts.noAction.toString()],
    ['Simulated', counts.simulated.toString()],
    ['Rejected', counts.rejected.toString()],
  ];

  return (
    <section className="summary-grid" aria-label="Security event summary">
      {cards.map(([label, value]) => (
        <article key={label} className="panel summary-card swiss-box">
          <div className="summary-label">{label}</div>
          <div className="summary-value">{value}</div>
        </article>
      ))}
    </section>
  );
}

