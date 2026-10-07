import { useEffect, useState } from 'react';
import { ApiError } from '../api/client';
import { fetchSimulations, runSimulation } from '../api/events';
import type { SecurityEvent, SimulationScenario } from '../types/api';
import { humanize } from '../lib/format';
import { ledgerHref } from '../lib/route';
import { describeError } from '../lib/useAegisApi';
import Icon, { type IconName } from './Icon';
import { LevelTag, OutcomeTag } from './Tags';

const ICONS: Record<string, IconName> = {
  syn_flood: 'flood',
  port_scan: 'scan',
  fast_scan: 'detect',
  slow_scan: 'clock',
  benign: 'observe',
};

/** Shown while the list loads, or when the connected API predates simulations. */
const KNOWN: SimulationScenario[] = [
  { id: 'syn_flood', name: 'SYN flood', summary: '60 SYN packets at one web port in 1.5 seconds, none of them completed.', flow_key_strategy: 'five_tuple', target: '10.0.0.1' },
  { id: 'port_scan', name: 'Port scan', summary: 'One host probes 32 ports on a server over 4.65 seconds.', flow_key_strategy: 'three_tuple', target: '10.0.0.2' },
  { id: 'fast_scan', name: 'Fast scan', summary: '24 common ports probed in 0.8 seconds: a port scan and a SYN flood at once.', flow_key_strategy: 'three_tuple', target: '10.0.0.4' },
  { id: 'slow_scan', name: 'Slow scan', summary: 'Exactly 20 ports probed over 3.8 seconds, right on the port-scan threshold.', flow_key_strategy: 'three_tuple', target: '10.0.0.12' },
  { id: 'benign', name: 'Normal DNS lookups', summary: 'Five ordinary DNS queries. Nothing should fire and nothing is stored.', flow_key_strategy: 'five_tuple', target: '10.0.0.53' },
];

const FLOW_KEYS: Record<string, string> = {
  five_tuple: 'Five-tuple',
  three_tuple: 'Three-tuple',
  bidirectional: 'Direction-independent',
};

type Availability = 'checking' | 'ready' | 'unsupported' | 'disabled' | 'offline';

type Outcome = {
  scenario: SimulationScenario;
  sourceIp: string;
  packets: number;
  event: SecurityEvent | null;
};

type SimulatorProps = {
  variant?: 'section' | 'console';
  /** Called after a run so the page can reload the ledger and focus the new event. */
  onSimulated: (eventId: string | null) => void;
};

function runError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'too_many_requests') return 'One simulation per second. Try again in a moment.';
    if (error.code === 'simulations_disabled') return 'Simulations are turned off on this server.';
  }
  return describeError(error);
}

export default function Simulator({ variant = 'section', onSimulated }: SimulatorProps) {
  const [scenarios, setScenarios] = useState<SimulationScenario[]>(KNOWN);
  const [availability, setAvailability] = useState<Availability>('checking');
  const [running, setRunning] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchSimulations()
      .then((data) => {
        if (cancelled) return;
        if (data.scenarios.length > 0) setScenarios(data.scenarios);
        setAvailability(data.enabled ? 'ready' : 'disabled');
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        const missing = reason instanceof ApiError && (reason.status === 404 || reason.status === 405);
        setAvailability(missing ? 'unsupported' : 'offline');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const run = async (scenario: SimulationScenario) => {
    setRunning(scenario.id);
    setError(null);
    try {
      const result = await runSimulation(scenario.id);
      const event = result.events[0] ?? null;
      setOutcome({ scenario: result.scenario, sourceIp: result.source_ip, packets: result.packets, event });
      onSimulated(event?.event_id ?? null);
    } catch (reason) {
      setError(runError(reason));
    } finally {
      setRunning(null);
    }
  };

  const usable = availability === 'ready';

  return (
    <div className={`sim sim--${variant}`}>
      <ul className="sim__grid">
        {scenarios.map((scenario) => (
          <li key={scenario.id}>
            <button
              type="button"
              className="sim-card"
              data-scenario={scenario.id}
              aria-busy={running === scenario.id}
              disabled={!usable || running !== null}
              onClick={() => void run(scenario)}
            >
              <span className="sim-card__top">
                <span className="sim-card__icon">
                  <Icon name={ICONS[scenario.id] ?? 'packet'} size={22} />
                </span>
                <span className="sim-card__go" aria-hidden="true">
                  {running === scenario.id ? <span className="sim-card__spinner" /> : <Icon name="arrow" size={16} />}
                </span>
              </span>
              <span className="sim-card__name">{scenario.name}</span>
              {variant === 'section' && <span className="sim-card__summary">{scenario.summary}</span>}
              <span className="sim-card__meta">
                {FLOW_KEYS[scenario.flow_key_strategy] ?? humanize(scenario.flow_key_strategy)} flows to{' '}
                <span className="mono">{scenario.target}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>

      <div className="sim__status" aria-live="polite">
        {availability === 'unsupported' && (
          <p className="sim__note">
            <Icon name="info" size={16} />
            <span>
              The connected API is an older version without simulations. Deploy the updated backend to enable them;
              until then, the rule lab runs the same rules in your browser.
            </span>
          </p>
        )}
        {availability === 'disabled' && (
          <p className="sim__note">
            <Icon name="lock" size={16} />
            <span>Simulations are turned off on this server (ALLOW_SIMULATIONS=false).</span>
          </p>
        )}
        {availability === 'offline' && (
          <p className="sim__note">
            <Icon name="info" size={16} />
            <span>The API cannot be reached, so simulations are unavailable right now.</span>
          </p>
        )}
        {error && (
          <p className="sim__note sim__note--error" role="alert">
            <Icon name="cross" size={16} />
            <span>{error}</span>
          </p>
        )}
        {outcome && !error && (
          <div className="sim__result" key={`${outcome.scenario.id}-${outcome.sourceIp}-${outcome.event?.event_id ?? 'none'}`}>
            <p className="sim__result-head">
              <Icon name={outcome.event ? 'record' : 'check'} size={18} />
              <span>
                <b>{outcome.scenario.name}</b>: {outcome.packets} synthetic packets from{' '}
                <span className="mono">{outcome.sourceIp}</span>
              </span>
            </p>
            {outcome.event ? (
              <p className="sim__result-body">
                <span>The engine stored a</span>
                <LevelTag level={outcome.event.risk.level} />
                <span>
                  event scoring <b>{outcome.event.risk.score}</b>, decided{' '}
                  <b>{humanize(outcome.event.policy.recommended_action).toLowerCase()}</b>, outcome
                </span>
                <OutcomeTag status={outcome.event.response.status} />
                <a className="text-link" href={ledgerHref({ event: outcome.event.event_id })}>
                  Inspect it
                </a>
              </p>
            ) : (
              <p className="sim__result-body">No rule fired, so the pipeline discarded the window and stored nothing.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
