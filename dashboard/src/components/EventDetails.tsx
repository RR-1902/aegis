import type { SecurityEvent } from '../types/api';
import { formatDateTime, formatFlowKey, titleCase } from '../utils/format';

type Props = {
  event: SecurityEvent | null;
  loading: boolean;
  error: string | null;
};

function renderValue(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}

export default function EventDetails({ event, loading, error }: Props) {
  if (loading) {
    return <aside className="panel details-panel swiss-box">Loading event details...</aside>;
  }

  if (error) {
    return <aside className="panel details-panel swiss-box error-message">{error}</aside>;
  }

  if (!event) {
    return <aside className="panel details-panel swiss-box empty-state">Select an event to inspect its security analysis.</aside>;
  }

  return (
    <aside className="panel details-panel swiss-box">
      <section>
        <h2>Event Identity</h2>
        <dl className="detail-grid">
          <div><dt>Event ID</dt><dd className="mono">{event.event_id}</dd></div>
          <div><dt>Flow Key</dt><dd className="mono">{formatFlowKey(event.flow_key)}</dd></div>
          <div><dt>Window Start</dt><dd className="mono">{formatDateTime(event.window_start)}</dd></div>
          <div><dt>Window End</dt><dd className="mono">{formatDateTime(event.window_end)}</dd></div>
          <div><dt>Recorded At</dt><dd className="mono">{formatDateTime(event.recorded_at)}</dd></div>
          <div><dt>Lifecycle Status</dt><dd><span className={`badge badge-${event.lifecycle_status}`}>{titleCase(event.lifecycle_status)}</span></dd></div>
        </dl>
      </section>

      <section>
        <h2>Causal Chain</h2>
        <p className="causal-chain">Detection → Risk → Policy → Response</p>
      </section>

      <section>
        <h2>Detection</h2>
        {event.detections.map((detection) => (
          <article key={`${detection.rule_id}-${detection.window_start}`} className="nested-card swiss-box">
            <div className="detail-heading-row">
              <h3>{detection.rule_name}</h3>
              <span className={`badge badge-${detection.severity}`}>{titleCase(detection.severity)}</span>
            </div>
            <dl className="detail-grid">
              <div><dt>Rule ID</dt><dd className="mono">{detection.rule_id}</dd></div>
              <div><dt>Window</dt><dd className="mono">{formatDateTime(detection.window_start)} → {formatDateTime(detection.window_end)}</dd></div>
              <div><dt>Explanation</dt><dd>{detection.explanation}</dd></div>
            </dl>
            <div>
              <dt>Evidence</dt>
              <pre className="code-block">{JSON.stringify(detection.evidence, null, 2)}</pre>
            </div>
          </article>
        ))}
      </section>

      <section>
        <h2>Risk</h2>
        <article className="nested-card swiss-box">
          <dl className="detail-grid">
            <div><dt>Score</dt><dd>{event.risk.score}</dd></div>
            <div><dt>Level</dt><dd><span className={`badge badge-${event.risk.level}`}>{titleCase(event.risk.level)}</span></dd></div>
            <div><dt>Explanation</dt><dd>{event.risk.explanation}</dd></div>
          </dl>
        </article>
      </section>

      <section>
        <h2>Policy</h2>
        <article className="nested-card swiss-box">
          <dl className="detail-grid">
            <div><dt>Recommended Action</dt><dd>{titleCase(event.policy.recommended_action)}</dd></div>
            <div><dt>Allowed</dt><dd>{event.policy.allowed ? 'Yes' : 'No'}</dd></div>
            <div><dt>Execution Mode</dt><dd>{titleCase(event.policy.execution_mode)}</dd></div>
            <div><dt>Risk Score</dt><dd>{event.policy.risk_score}</dd></div>
            <div><dt>Risk Level</dt><dd>{titleCase(event.policy.risk_level)}</dd></div>
            <div><dt>Target</dt><dd className="mono">{event.policy.target ? renderValue(event.policy.target) : 'None'}</dd></div>
            <div><dt>Explanation</dt><dd>{event.policy.explanation}</dd></div>
          </dl>
        </article>
      </section>

      <section>
        <h2>Response</h2>
        <article className="nested-card swiss-box">
          <dl className="detail-grid">
            <div><dt>Action</dt><dd>{titleCase(event.response.action)}</dd></div>
            <div><dt>Status</dt><dd><span className={`badge badge-${event.response.status}`}>{titleCase(event.response.status)}</span></dd></div>
            <div><dt>Simulated</dt><dd>{event.response.simulated ? 'Yes' : 'No'}</dd></div>
            <div><dt>Message</dt><dd>{event.response.message}</dd></div>
            <div><dt>Error</dt><dd>{event.response.error ?? 'None'}</dd></div>
            <div><dt>Timestamp</dt><dd className="mono">{formatDateTime(event.response.timestamp)}</dd></div>
          </dl>
        </article>
      </section>
    </aside>
  );
}

