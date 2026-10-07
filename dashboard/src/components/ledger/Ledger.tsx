import { useEffect, useMemo, useRef } from 'react';
import type { AegisApi } from '../../lib/useAegisApi';
import { useEventDetail } from '../../lib/useAegisApi';
import { LEVELS } from '../../lib/engine';
import { formatClock, formatDateTime, formatFlow, formatRelative, humanize, isSyntheticSource } from '../../lib/format';
import { ledgerHref } from '../../lib/route';
import Simulator from '../Simulator';
import { OutcomeTag, SyntheticTag } from '../Tags';
import Distribution from './Distribution';
import EventInspector from './EventInspector';
import FilterGroup from './FilterGroup';

type LedgerProps = {
  api: AegisApi;
  params: URLSearchParams;
  navigate: (href: string, options?: { replace?: boolean }) => void;
};

const OUTCOMES = ['no_action', 'simulated', 'rejected'];

export default function Ledger({ api, params, navigate }: LedgerProps) {
  const risk = params.get('risk') ?? '';
  const outcome = params.get('status') ?? '';
  const selectedId = params.get('event');
  const all = useMemo(() => api.events.data ?? [], [api.events.data]);

  const visible = useMemo(
    () =>
      all.filter(
        (event) =>
          (!risk || event.risk.level.toLowerCase() === risk) &&
          (!outcome || event.lifecycle_status.toLowerCase() === outcome),
      ),
    [all, risk, outcome],
  );

  const fallback = useMemo(() => all.find((event) => event.event_id === selectedId) ?? null, [all, selectedId]);
  const detail = useEventDetail(selectedId, fallback);

  const inspectorRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (selectedId && window.matchMedia('(max-width: 960px)').matches) {
      inspectorRef.current?.scrollIntoView({ block: 'start' });
    }
  }, [selectedId]);

  const setFilter = (key: 'risk' | 'status', value: string) => {
    navigate(
      ledgerHref({
        risk: key === 'risk' ? value : risk,
        status: key === 'status' ? value : outcome,
        event: selectedId,
      }),
      { replace: true },
    );
  };

  const countWhere = (test: (level: string, status: string) => boolean) =>
    all.filter((event) => test(event.risk.level.toLowerCase(), event.lifecycle_status.toLowerCase())).length;

  return (
    <main className="ledger" id="main" tabIndex={-1}>
      <header className="ledger__head">
        <div>
          <h1 className="heading">Event ledger</h1>
          <p className="muted">
            Security events stored by the AEGIS pipeline, newest first. Select one to see its full decision chain.
          </p>
        </div>
        <div className="ledger__sync">
          <p className="muted" aria-live="polite">
            {api.events.loading
              ? api.events.slow
                ? 'Waking the API…'
                : 'Loading…'
              : api.syncedAt
                ? `Synced at ${formatClock(api.syncedAt)}`
                : 'Not synced'}
          </p>
          <button type="button" className="button" onClick={api.refresh} disabled={api.events.loading}>
            Refresh
          </button>
        </div>
      </header>

      <section className="ledger__simulate" aria-labelledby="simulate-title">
        <h2 id="simulate-title" className="ledger__subhead">
          Simulate an attack
          <span className="muted">Runs synthetic packets through the real pipeline and stores the verdict.</span>
        </h2>
        <Simulator
          variant="console"
          onSimulated={(eventId) => {
            api.refresh();
            if (eventId) navigate(ledgerHref({ event: eventId }));
          }}
        />
      </section>

      {api.events.data && <Distribution events={all} />}

      <div className="ledger__filters">
        <FilterGroup
          legend="Risk level"
          name="risk"
          value={risk}
          onChange={(value) => setFilter('risk', value)}
          options={[
            { value: '', label: 'All', count: all.length },
            ...LEVELS.map((level) => ({
              value: level,
              label: humanize(level),
              count: countWhere((value) => value === level),
            })),
          ]}
        />
        <FilterGroup
          legend="Outcome"
          name="status"
          value={outcome}
          onChange={(value) => setFilter('status', value)}
          options={[
            { value: '', label: 'All', count: all.length },
            ...OUTCOMES.map((status) => ({
              value: status,
              label: humanize(status),
              count: countWhere((_, value) => value === status),
            })),
          ]}
        />
      </div>

      <div className="ledger__grid">
        <section className="ledger__list" aria-label="Events">
          <EventList
            api={api}
            events={visible}
            selectedId={selectedId}
            risk={risk}
            outcome={outcome}
            onClear={() => navigate(ledgerHref({ event: selectedId }), { replace: true })}
          />
        </section>
        <div className="ledger__inspector" ref={inspectorRef}>
          <EventInspector event={detail.data} loading={detail.loading} error={detail.error} />
        </div>
      </div>
    </main>
  );
}

type EventListProps = {
  api: AegisApi;
  events: NonNullable<AegisApi['events']['data']>;
  selectedId: string | null;
  risk: string;
  outcome: string;
  onClear: () => void;
};

function EventList({ api, events, selectedId, risk, outcome, onClear }: EventListProps) {
  if (api.events.loading && !api.events.data) {
    return (
      <div className="list-state" role="status">
        <p>{api.events.slow ? 'Waking the API…' : 'Loading events…'}</p>
        {api.events.slow && (
          <p className="muted">The hosted API sleeps when idle. The first request can take up to a minute.</p>
        )}
      </div>
    );
  }

  if (api.events.error && !api.events.data) {
    return (
      <div className="list-state" role="alert">
        <p>{api.events.error}</p>
        <button type="button" className="button" onClick={api.refresh}>
          Retry
        </button>
      </div>
    );
  }

  if ((api.events.data ?? []).length === 0) {
    return (
      <div className="list-state">
        <p>No security events recorded yet.</p>
        <p className="muted">
          Start the pipeline with <code>python -m app.main</code> on a machine with capture rights, then refresh.
        </p>
      </div>
    );
  }

  if (events.length === 0) {
    return (
      <div className="list-state">
        <p>No events match these filters.</p>
        <button type="button" className="button" onClick={onClear}>
          Clear filters
        </button>
      </div>
    );
  }

  return (
    <ol className="rows">
      {events.map((event) => {
        const level = event.risk.level.toLowerCase();
        const selected = event.event_id === selectedId;
        return (
          <li key={event.event_id}>
            <a
              className="row"
              href={ledgerHref({ risk, status: outcome, event: event.event_id })}
              aria-current={selected ? 'true' : undefined}
              data-level={level}
            >
              <span className="row__score" data-level={level}>
                {event.risk.score}
                <span className="row__level">{humanize(level)}</span>
              </span>
              <span className="row__main">
                <span className="row__rule">
                  {event.detections.map((detection) => detection.rule_name).join(' + ') || 'No detection'}
                  {isSyntheticSource(event.flow_key.src_ip) && <SyntheticTag />}
                </span>
                <span className="row__flow mono" translate="no">
                  {formatFlow(event.flow_key)}
                </span>
              </span>
              <span className="row__outcome">
                <OutcomeTag status={event.lifecycle_status} />
              </span>
              <time className="row__time" dateTime={event.recorded_at} title={formatDateTime(event.recorded_at)}>
                {formatRelative(event.recorded_at)}
              </time>
            </a>
          </li>
        );
      })}
    </ol>
  );
}
