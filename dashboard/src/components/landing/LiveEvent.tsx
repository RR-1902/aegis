import type { AegisApi } from '../../lib/useAegisApi';
import { formatDateTime, formatFlow, formatRelative, isSyntheticSource } from '../../lib/format';
import { ledgerHref } from '../../lib/route';
import { usePauseOffscreen } from '../../lib/motion';
import Icon from '../Icon';
import Simulator from '../Simulator';
import { SyntheticTag } from '../Tags';
import TraceSummary from '../TraceSummary';
import SectionHead from './SectionHead';

/** `security-event:a052b98a…` → `a052b98a bb263171 …`, eight characters a group. */
function groupHash(eventId: string): string {
  const hash = eventId.replace(/^security-event:/, '');
  return hash.match(/.{1,8}/g)?.join(' ') ?? hash;
}

type LiveEventProps = {
  events: AegisApi['events'];
  onRetry: () => void;
  onSimulated: () => void;
};

export default function LiveEvent({ events, onRetry, onSimulated }: LiveEventProps) {
  const latest = events.data?.[0] ?? null;
  const sectionRef = usePauseOffscreen<HTMLElement>();

  return (
    <section className="section live" id="simulate" aria-labelledby="live-title" ref={sectionRef}>
      <SectionHead id="live-title" label="Simulate an attack" icon="flood" title="Launch an attack. Watch the verdict.">
        <p>
          Pick an attack below. The server builds the packets in memory, runs them through the real pipeline, and
          stores whatever the engine decides. The panel underneath reads the newest event back from{' '}
          <code>GET /events</code>, exactly as the console does.
        </p>
      </SectionHead>

      <div data-reveal="">
        <Simulator onSimulated={onSimulated} />
      </div>

      <figure className="latest" data-reveal="" aria-busy={events.loading}>
        <figcaption className="latest__head">
          <span className="latest__title">
            <span className="latest__pulse" aria-hidden="true" />
            Latest recorded event
          </span>
          {latest && (
            <span className="latest__meta">
              <time dateTime={latest.recorded_at} title={formatDateTime(latest.recorded_at)}>
                Recorded {formatRelative(latest.recorded_at)}
              </time>
              <a className="text-link" href={ledgerHref({ event: latest.event_id })}>
                Inspect in the console
              </a>
            </span>
          )}
        </figcaption>

        {latest ? (
          <>
            <p className="latest__flow" translate="no">
              {formatFlow(latest.flow_key)}
              {isSyntheticSource(latest.flow_key.src_ip) && <SyntheticTag />}
            </p>
            <TraceSummary key={latest.event_id} event={latest} />
            <p className="latest__id">
              <span>
                <Icon name="hash" size={14} /> Event ID, SHA-256 of the flow key and window
              </span>
              <span className="latest__hash mono" translate="no">
                {groupHash(latest.event_id)}
              </span>
            </p>
          </>
        ) : events.loading ? (
          <div className="latest__state" role="status">
            <p>{events.slow ? 'Waking the API…' : 'Loading the latest event…'}</p>
            {events.slow && (
              <p className="muted">The hosted API sleeps when nobody is using it. The first request can take up to a minute.</p>
            )}
          </div>
        ) : events.error ? (
          <div className="latest__state" role="alert">
            <p>{events.error}</p>
            <button type="button" className="button" onClick={onRetry}>
              <Icon name="refresh" size={16} />
              Retry
            </button>
          </div>
        ) : (
          <div className="latest__state">
            <p>No events recorded yet.</p>
            <p className="muted">
              Seed real engine events with <code>python -m scripts.seed_demo_attacks</code>, or run the capture
              pipeline with <code>python -m app.main</code>.
            </p>
          </div>
        )}
      </figure>
    </section>
  );
}
