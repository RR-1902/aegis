import Icon from '../Icon';
import SectionHead from './SectionHead';

const DOES = [
  'Captures and parses live traffic on the machine it runs on.',
  'Detects SYN floods and port scans with explicit, configurable thresholds.',
  'Keeps the evidence behind every alert: feature values, thresholds and each comparison.',
  'Stores each alert once, under a SHA-256 identifier derived from its flow and window.',
  'Serves recorded events through a read-only REST API and this console.',
];

const NEXT = [
  'Block traffic. Every response is simulated, and no firewall executor exists yet.',
  'Recommend a block from live traffic. The rules do not yet name a source in their evidence.',
  'Catch port scans with the default runtime. Five-tuple flows split a scan apart; the three-tuple key is needed.',
  'Report an attack the moment it starts. A window is handed on only after it closes and later traffic arrives.',
  'Detect ICMP floods, RST anomalies, brute force or volumetric spikes.',
  'Use machine learning. All detection today is threshold-based.',
  'Capture traffic in the hosted demo. The hosted API serves events from a bundled database.',
];

export default function Scope() {
  return (
    <section className="section scope" id="scope" aria-labelledby="scope-title">
      <SectionHead id="scope-title" label="Scope" icon="evidence" title="What it does today, and what comes next">
        <p>An honest boundary, so the claims on this page can all be checked against the code.</p>
      </SectionHead>
      <div className="scope__cols">
        <div className="scope__col" data-reveal="">
          <h3>
            <span className="scope__badge scope__badge--done">
              <Icon name="check" size={16} />
            </span>
            Does today
          </h3>
          <ul>
            {DOES.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
        <div className="scope__col" data-reveal="">
          <h3>
            <span className="scope__badge">
              <Icon name="clock" size={16} />
            </span>
            Not yet
          </h3>
          <ul>
            {NEXT.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
