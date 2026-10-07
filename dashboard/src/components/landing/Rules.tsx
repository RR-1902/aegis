import { LEVEL_BOUNDS, POINTS, THRESHOLDS } from '../../lib/engine';
import Icon from '../Icon';
import Term from '../Term';
import SectionHead from './SectionHead';

const LEVELS = [
  { level: 'low', label: 'Low', range: `0–${LEVEL_BOUNDS.low}`, action: 'Log only', detail: 'Recorded quietly. No alert, no action.' },
  {
    level: 'medium',
    label: 'Medium',
    range: `${LEVEL_BOUNDS.low + 1}–${LEVEL_BOUNDS.medium}`,
    action: 'Alert only',
    detail: 'Recorded as an alert for a person to review.',
  },
  {
    level: 'high',
    label: 'High',
    range: `${LEVEL_BOUNDS.medium + 1}–${LEVEL_BOUNDS.high}`,
    action: 'Block source, if attributable',
    detail: 'Only with a SYN flood and an observed source in the evidence. Otherwise alert only.',
  },
  {
    level: 'critical',
    label: 'Critical',
    range: `${LEVEL_BOUNDS.high + 1}–100`,
    action: 'Block source, if attributable',
    detail: 'With a SYN flood or a critical port scan, and an observed source. Otherwise alert only.',
  },
];

export default function Rules() {
  return (
    <section className="section rules" id="rules" aria-labelledby="rules-title">
      <SectionHead id="rules-title" label="Detection rules" icon="detect" title="Two rules. One transparent score.">
        <p>
          Every threshold and every point value is configuration in <code>app/config/settings.py</code>, not
          something learned from data. Change a number and the verdicts change with it, predictably.
        </p>
      </SectionHead>

      <div className="rule-cards">
        <article className="rule-card" data-reveal="">
          <header className="rule-card__head">
            <span className="rule-card__icon">
              <Icon name="flood" size={24} />
            </span>
            <div>
              <h3>SYN Flood</h3>
              <p>Floods a server with connection requests it never finishes.</p>
            </div>
          </header>
          <div className="rule-card__when">
            <p className="rule-card__label">Fires when both are true in one window</p>
            <p className="condition">
              <code>syn_rate</code>
              <span>≥ {THRESHOLDS.synRate} per second</span>
            </p>
            <p className="condition">
              <code>incomplete_connection_ratio</code>
              <span>≥ {THRESHOLDS.synIncompleteRatio}</span>
            </p>
          </div>
          <dl className="rule-card__points">
            <div>
              <dt>
                Medium <Term id="severity">severity</Term>
              </dt>
              <dd>
                <b>+{POINTS.syn_flood.medium}</b>
                <span>A value sits exactly on its threshold</span>
              </dd>
            </div>
            <div>
              <dt>High severity</dt>
              <dd>
                <b>+{POINTS.syn_flood.high}</b>
                <span>Both values clear their thresholds</span>
              </dd>
            </div>
          </dl>
        </article>

        <article className="rule-card" data-reveal="">
          <header className="rule-card__head">
            <span className="rule-card__icon">
              <Icon name="scan" size={24} />
            </span>
            <div>
              <h3>Port Scan</h3>
              <p>Probes many ports on one host to map its services.</p>
            </div>
          </header>
          <div className="rule-card__when">
            <p className="rule-card__label">Fires when, in one window</p>
            <p className="condition">
              <code>unique_destination_ports</code>
              <span>≥ {THRESHOLDS.portScanPorts}</span>
            </p>
            <p className="rule-card__note">
              <Icon name="info" size={16} />
              <span>
                Visible only with <Term id="three-tuple">three-tuple</Term> flows, where one attacker’s probes
                share a flow.
              </span>
            </p>
          </div>
          <dl className="rule-card__points">
            <div>
              <dt>Medium severity</dt>
              <dd>
                <b>+{POINTS.port_scan.medium}</b>
                <span>Exactly {THRESHOLDS.portScanPorts} ports</span>
              </dd>
            </div>
            <div>
              <dt>High severity</dt>
              <dd>
                <b>+{POINTS.port_scan.high}</b>
                <span>More than {THRESHOLDS.portScanPorts} ports</span>
              </dd>
            </div>
          </dl>
        </article>
      </div>

      <div className="levels" data-reveal="">
        <div className="levels__head">
          <h3>
            <Icon name="level" size={20} />
            From points to action
          </h3>
          <p>
            Points from every rule that fired on the same window are added and capped at 100. The{' '}
            <Term id="risk-level">level</Term> decides the <Term id="policy">policy</Term>.
          </p>
        </div>
        <ol className="levels__list">
          {LEVELS.map((item) => (
            <li className="level-card" data-level={item.level} key={item.level}>
              <span className="level-card__bar" />
              <p className="level-card__name">
                {item.label}
                <span className="mono">{item.range}</span>
              </p>
              <p className="level-card__action">{item.action}</p>
              <p className="level-card__detail">{item.detail}</p>
            </li>
          ))}
        </ol>
        <p className="levels__safe">
          <Icon name="lock" size={18} />
          <span>
            With <Term id="safe-mode">SAFE_MODE</Term> on, which is the default, any block is simulated. With it off,
            the response engine rejects the block, because no firewall executor exists.
          </span>
        </p>
      </div>
    </section>
  );
}
