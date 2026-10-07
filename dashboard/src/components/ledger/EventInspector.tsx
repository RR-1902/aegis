import { useEffect, useState, type CSSProperties, type ReactNode } from 'react';
import type { SecurityEvent } from '../../types/api';
import {
  formatDateTime,
  formatEndpoint,
  formatFlow,
  humanize,
  isSyntheticSource,
  shortEventId,
  windowSeconds,
} from '../../lib/format';
import RiskMeter from '../RiskMeter';
import { LevelTag, OutcomeTag, SyntheticTag } from '../Tags';
import EvidenceView from './EvidenceView';

type InspectorProps = {
  event: SecurityEvent | null;
  loading: boolean;
  error: string | null;
};

function Field({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined}>{children}</dd>
    </div>
  );
}

function Step({ index, title, children }: { index: number; title: string; children: ReactNode }) {
  return (
    <li className="inspector__step" style={{ '--i': index } as CSSProperties}>
      <h3 className="inspector__title">
        <span className="inspector__index">{index}</span>
        {title}
      </h3>
      {children}
    </li>
  );
}

function CopyId({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return undefined;
    const timer = window.setTimeout(() => setCopied(false), 1800);
    return () => window.clearTimeout(timer);
  }, [copied]);
  return (
    <button
      type="button"
      className="button button--small"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => setCopied(true));
      }}
    >
      <span aria-live="polite">{copied ? 'Copied' : 'Copy ID'}</span>
    </button>
  );
}

export default function EventInspector({ event, loading, error }: InspectorProps) {
  if (error) {
    return (
      <div className="inspector inspector--state" role="alert">
        <p>{error}</p>
      </div>
    );
  }

  if (!event) {
    return (
      <div className="inspector inspector--state">
        <p className="inspector__prompt">{loading ? 'Loading event…' : 'Select an event to see how AEGIS reached its verdict.'}</p>
        {!loading && (
          <p className="muted">
            Each event records the flow window, the rules that fired with their evidence, the risk score, the
            policy decision and the response.
          </p>
        )}
      </div>
    );
  }

  const seconds = windowSeconds(event.window_start, event.window_end);
  const level = event.risk.level.toLowerCase();

  return (
    <article className="inspector" aria-labelledby="inspector-title" aria-busy={loading}>
      <header className="inspector__head">
        <div>
          <h2 id="inspector-title" className="inspector__heading">
            Event <span className="mono" translate="no">{shortEventId(event.event_id)}</span>
          </h2>
          <p className="inspector__flow mono" translate="no">
            {formatFlow(event.flow_key)}
          </p>
          {isSyntheticSource(event.flow_key.src_ip) && (
            <p className="inspector__synthetic">
              <SyntheticTag />
              <span>
                The source is a documentation address that never appears on a real network, so this event came from a
                simulation run through the real pipeline.
              </span>
            </p>
          )}
        </div>
        <CopyId value={event.event_id} />
      </header>

      <ol className="inspector__steps" key={event.event_id}>
        <Step index={1} title="Flow window">
          <dl className="fields">
            <Field label="Source" mono>
              {formatEndpoint(event.flow_key.src_ip, event.flow_key.src_port)}
            </Field>
            <Field label="Destination" mono>
              {formatEndpoint(event.flow_key.dst_ip, event.flow_key.dst_port)}
            </Field>
            <Field label="Protocol">{event.flow_key.protocol}</Field>
            <Field label="Length">{seconds === null ? '—' : `${seconds} seconds`}</Field>
            <Field label="Opened">{formatDateTime(event.window_start)}</Field>
            <Field label="Closed">{formatDateTime(event.window_end)}</Field>
          </dl>
        </Step>

        <Step index={2} title={event.detections.length === 1 ? 'Detection' : `Detections (${event.detections.length})`}>
          {event.detections.length === 0 && <p className="muted">No detections were stored with this event.</p>}
          {event.detections.map((detection) => (
            <div className="detection" key={`${detection.rule_id}-${detection.window_start}`}>
              <p className="detection__head">
                <span className="detection__name">{detection.rule_name}</span>
                <LevelTag level={detection.severity} />
                <code className="detection__id">{detection.rule_id}</code>
              </p>
              <p>{detection.explanation}</p>
              <EvidenceView evidence={detection.evidence} />
            </div>
          ))}
        </Step>

        <Step index={3} title="Risk">
          <p className="inspector__score" data-level={level}>
            {event.risk.score}
            <span className="trace__of">/100</span>
            <LevelTag level={level} />
          </p>
          <RiskMeter score={event.risk.score} level={level} scale />
          <p>{event.risk.explanation}</p>
        </Step>

        <Step index={4} title="Policy">
          <dl className="fields">
            <Field label="Decision">{humanize(event.policy.recommended_action)}</Field>
            <Field label="Execution">{humanize(event.policy.execution_mode)}</Field>
            <Field label="Allowed">{event.policy.allowed ? 'Yes' : 'No'}</Field>
            <Field label="Target" mono>
              {event.policy.target
                ? `${formatEndpoint(event.policy.target.ip, event.policy.target.port)} (${humanize(event.policy.target.role).toLowerCase()})`
                : 'None'}
            </Field>
          </dl>
          <p>{event.policy.explanation}</p>
        </Step>

        <Step index={5} title="Response">
          <p className="inspector__outcome">
            <OutcomeTag status={event.response.status} />
            <span className="muted">{formatDateTime(event.response.timestamp)}</span>
          </p>
          <p>{event.response.message}</p>
          {event.response.error && <p className="inspector__error">{event.response.error}</p>}
        </Step>
      </ol>

      <details className="raw">
        <summary>Stored record (JSON)</summary>
        <pre className="raw__code" translate="no">
          {JSON.stringify(event, null, 2)}
        </pre>
      </details>

      <p className="inspector__foot muted">
        Recorded {formatDateTime(event.recorded_at)}. ID{' '}
        <span className="mono break" translate="no">
          {event.event_id}
        </span>
      </p>
    </article>
  );
}
