import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import Icon from '../Icon';
import { ATTACK } from './attack';

type SceneProps = { active: boolean };

const d = (seconds: number) => ({ '--d': `${seconds}s` }) as CSSProperties;

function Scene({ name, active, children }: { name: string; active: boolean; children: ReactNode }) {
  return (
    <div className={`scene scene--${name}${active ? ' is-active' : ''}`} aria-hidden={!active}>
      {children}
    </div>
  );
}

/* 1. Capture: probes cross the wire and pass the BPF filter; ICMP is filtered out. */
export function CaptureScene({ active }: SceneProps) {
  const travellers = ATTACK.ports.slice(0, 7).map((port, index) => ({ label: `SYN :${port}`, kind: 'syn', delay: index * 0.38 }));
  return (
    <Scene name="capture" active={active}>
      <div className="sc-endpoints">
        <div className="sc-node" style={d(0.05)}>
          <span className="sc-node__icon sc-node__icon--threat">
            <Icon name="source" size={22} />
          </span>
          <span className="mono">{ATTACK.source}</span>
          <small>Attacker</small>
        </div>
        <div className="sc-node sc-node--end" style={d(0.15)}>
          <span className="sc-node__icon">
            <Icon name="server" size={22} />
          </span>
          <span className="mono">{ATTACK.target}</span>
          <small>Protected server</small>
        </div>
      </div>
      <div className="sc-wire" style={d(0.2)}>
        <span className="sc-wire__line" />
        <span className="sc-gate">
          <Icon name="filter" size={16} />
          BPF <code>tcp or udp</code>
        </span>
        {travellers.map((item) => (
          <span className="sc-travel" key={item.label} style={d(item.delay)}>
            <span className="chip chip--small" data-level="critical">
              <span className="chip__flag">{item.label}</span>
            </span>
          </span>
        ))}
        <span className="sc-travel sc-travel--dropped" style={d(1.3)}>
          <span className="chip chip--small chip--muted">
            <span className="chip__flag">ICMP echo</span>
          </span>
        </span>
      </div>
      <dl className="sc-stats">
        <div style={d(0.4)}>
          <dt>SYN packets</dt>
          <dd>{ATTACK.ports.length}</dd>
        </div>
        <div style={d(0.5)}>
          <dt>Ports probed</dt>
          <dd>{ATTACK.ports.length}</dd>
        </div>
        <div style={d(0.6)}>
          <dt>Elapsed</dt>
          <dd>{ATTACK.spanSeconds} s</dd>
        </div>
      </dl>
    </Scene>
  );
}

/* 2. Parse: one probe unpacked layer by layer. */
export function ParseScene({ active }: SceneProps) {
  const layers = [
    { name: 'Ethernet', tone: 'l2', fields: [['src_mac', '00:11:22:33:44:55'], ['dst_mac', '66:77:88:99:aa:bb']] },
    { name: 'IPv4', tone: 'l3', fields: [['src_ip', ATTACK.source], ['dst_ip', ATTACK.target], ['ttl', '64']] },
    { name: 'TCP', tone: 'l4', fields: [['src_port', '50000'], ['dst_port', String(ATTACK.ports[0])], ['flags', 'SYN']] },
  ];
  return (
    <Scene name="parse" active={active}>
      <p className="sc-caption" style={d(0)}>
        <Icon name="packet" size={16} /> Probe 1 of {ATTACK.ports.length}, 54 bytes on the wire
      </p>
      <div className="sc-layers">
        {layers.map((layer, index) => (
          <div className="sc-layer" data-tone={layer.tone} key={layer.name} style={d(0.15 + index * 0.18)}>
            <span className="sc-layer__name">{layer.name}</span>
            <dl className="sc-layer__fields">
              {layer.fields.map(([key, value]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd data-flag={key === 'flags' ? '' : undefined}>{value}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}
        <div className="sc-layer sc-layer--payload" style={d(0.75)}>
          <span className="sc-layer__name">Payload</span>
          <span className="sc-layer__note">Never read, never stored</span>
        </div>
      </div>
    </Scene>
  );
}

/* 3. Flows: 24 probes collapse into one three-tuple flow. */
export function FlowScene({ active }: SceneProps) {
  return (
    <Scene name="flow" active={active}>
      <div className="sc-ports">
        {ATTACK.ports.map((port, index) => (
          <span className="sc-port" key={port} style={d(index * 0.025)}>
            {port}
          </span>
        ))}
      </div>
      <div className="sc-lane" style={d(1.05)}>
        <Icon name="key" size={18} />
        <span className="mono">
          {ATTACK.source} → {ATTACK.target} TCP
        </span>
        <span className="sc-lane__count">{ATTACK.ports.length} packets, 1 flow</span>
      </div>
      <div className="sc-compare">
        <p className="sc-compare__row sc-compare__row--off" style={d(1.3)}>
          <span>Five-tuple key</span>
          <span>24 flows of 1 packet: the scan is invisible</span>
        </p>
        <p className="sc-compare__row" style={d(1.45)}>
          <span>Three-tuple key</span>
          <span>1 flow of 24 packets: the scan is measurable</span>
        </p>
      </div>
    </Scene>
  );
}

/* 4. Windows: the burst lands inside one five-second window. */
export function WindowScene({ active }: SceneProps) {
  const seconds = [0, 1, 2, 3, 4, 5];
  return (
    <Scene name="window" active={active}>
      <div className="sc-timeline">
        <div className="sc-bracket" style={d(0.1)}>
          <span>One window, 5 seconds</span>
        </div>
        <div className="sc-axis">
          {seconds.map((second) => (
            <span className="sc-axis__tick" key={second} style={{ left: `${second * 20}%` }}>
              <span>{second} s</span>
            </span>
          ))}
          {ATTACK.ports.map((port, index) => (
            <span
              className="sc-hit"
              key={port}
              style={{ left: `${((index / (ATTACK.ports.length - 1)) * ATTACK.spanSeconds * 100) / 5}%`, ...d(0.35 + index * 0.03) }}
            />
          ))}
          <span className="sc-close" style={d(1.35)}>
            <span>Window closes</span>
          </span>
        </div>
      </div>
      <p className="sc-note" style={d(1.6)}>
        <Icon name="window" size={16} />
        All 24 probes arrive in the first 0.8 s. After the window closes, AEGIS summarises it exactly once.
      </p>
    </Scene>
  );
}

/* 5. Features: the window becomes numbers; three of them matter to the rules. */
export function FeatureScene({ active }: SceneProps) {
  const rows = [
    { key: 'syn_rate', value: '30.0 per second', bar: 0.5, key3: true },
    { key: 'incomplete_connection_ratio', value: '1.0', bar: 1, key3: true },
    { key: 'unique_destination_ports', value: '24', bar: 0.5, key3: true },
    { key: 'packet_count', value: '24' },
    { key: 'connection_attempts', value: '24' },
    { key: 'successful_connections', value: '0' },
    { key: 'duration_seconds', value: '0.8' },
  ];
  return (
    <Scene name="features" active={active}>
      <ul className="sc-features">
        {rows.map((row, index) => (
          <li className={row.key3 ? 'sc-feature sc-feature--key' : 'sc-feature'} key={row.key} style={d(index * 0.08)}>
            <code>{row.key}</code>
            <span className="sc-feature__value">{row.value}</span>
            {row.bar !== undefined && (
              <span className="sc-feature__bar">
                <span style={{ transform: `scaleX(${row.bar})`, ...d(0.3 + index * 0.08) }} />
              </span>
            )}
          </li>
        ))}
      </ul>
      <p className="sc-note" style={d(0.8)}>
        <Icon name="features" size={16} />
        Plus 21 more features, all stored with the observation.
      </p>
    </Scene>
  );
}

function Gauge({ label, value, threshold, max, text }: { label: string; value: number; threshold: number; max: number; text: string }) {
  return (
    <div className="sc-gauge">
      <p className="sc-gauge__head">
        <code>{label}</code>
        <span>{text}</span>
      </p>
      <span className="sc-gauge__track">
        <span className="sc-gauge__fill" style={{ transform: `scaleX(${Math.min(value / max, 1)})` }} />
        <span className="sc-gauge__mark" style={{ left: `${(threshold / max) * 100}%` }} />
      </span>
    </div>
  );
}

/* 6. Detect: both rules fire and both clear their thresholds. */
export function DetectScene({ active }: SceneProps) {
  return (
    <Scene name="detect" active={active}>
      <div className="sc-rule" style={d(0)}>
        <p className="sc-rule__head">
          <Icon name="scan" size={18} />
          Port Scan
          <span className="sc-stamp" style={d(0.9)}>
            Fired, high
          </span>
        </p>
        <Gauge label="unique_destination_ports" value={24} threshold={20} max={40} text="24 ≥ 20" />
        <p className="sc-rule__why" style={d(1)}>More than 20 ports, so the severity is high.</p>
      </div>
      <div className="sc-rule" style={d(0.25)}>
        <p className="sc-rule__head">
          <Icon name="flood" size={18} />
          SYN Flood
          <span className="sc-stamp" style={d(1.15)}>
            Fired, high
          </span>
        </p>
        <Gauge label="syn_rate" value={30} threshold={10} max={40} text="30.0 ≥ 10" />
        <Gauge label="incomplete_connection_ratio" value={1} threshold={0.7} max={1} text="1.0 ≥ 0.7" />
        <p className="sc-rule__why" style={d(1.25)}>Both values above their thresholds, so the severity is high.</p>
      </div>
    </Scene>
  );
}

/* 7. Score: 40 + 55 = 95, critical. */
export function ScoreScene({ active }: SceneProps) {
  return (
    <Scene name="score" active={active}>
      <p className="sc-total" data-level="critical" style={d(0.9)}>
        95<span>/100</span>
      </p>
      <div className="sc-sum">
        <span className="sc-sum__part" style={d(0.1)}>
          Port Scan, high <b>+40</b>
        </span>
        <span className="sc-sum__part" style={d(0.35)}>
          SYN Flood, high <b>+55</b>
        </span>
      </div>
      <div className="sc-ladder">
        <span className="sc-ladder__band" data-level="low" />
        <span className="sc-ladder__band" data-level="medium" />
        <span className="sc-ladder__band" data-level="high" />
        <span className="sc-ladder__band" data-level="critical" />
        <span className="sc-ladder__seg sc-ladder__seg--a" style={d(0.2)} />
        <span className="sc-ladder__seg sc-ladder__seg--b" style={d(0.45)} />
        <span className="sc-ladder__marker" style={d(0.95)}>
          <span>95</span>
        </span>
      </div>
      <div className="sc-ladder__labels">
        <span>Low 0–29</span>
        <span>Medium 30–59</span>
        <span>High 60–79</span>
        <span data-level="critical">Critical 80–100</span>
      </div>
    </Scene>
  );
}

/* 8. Decide: block is considered, then refused for lack of an observed source. */
export function DecideScene({ active }: SceneProps) {
  return (
    <Scene name="decide" active={active}>
      <div className="sc-options">
        <span className="sc-options__plate" />
        <div className="sc-option">
          <Icon name="ledger" size={18} />
          <span>
            <b>Log only</b>
            <small>Low risk</small>
          </span>
        </div>
        <div className="sc-option sc-option--chosen">
          <Icon name="severity" size={18} />
          <span>
            <b>Alert only</b>
            <small>Chosen: raise an alert, take no action</small>
          </span>
          <span className="sc-option__tick">
            <Icon name="check" size={16} />
          </span>
        </div>
        <div className="sc-option sc-option--refused">
          <Icon name="lock" size={18} />
          <span>
            <b>Block source</b>
            <small>Needs an observed source in the evidence. None was recorded.</small>
          </span>
        </div>
      </div>
    </Scene>
  );
}

/* 9. Respond: the validation chain, then the outcome. */
export function RespondScene({ active }: SceneProps) {
  const checks = [
    'Decision is a well-formed policy decision',
    'Action is one AEGIS supports',
    'Execution mode is valid',
    'An alert needs no execution',
    'No target is required',
    'SAFE_MODE is consistent with the decision',
  ];
  return (
    <Scene name="respond" active={active}>
      <ul className="sc-checks">
        {checks.map((check, index) => (
          <li key={check} style={d(index * 0.14)}>
            <span className="sc-checks__icon">
              <Icon name="check" size={14} />
            </span>
            {check}
          </li>
        ))}
      </ul>
      <div className="sc-outcome" style={d(0.95)}>
        <Icon name="simulate" size={28} />
        <span>
          <b>No action</b>
          <small>Nothing on the host or the firewall changed.</small>
        </span>
      </div>
    </Scene>
  );
}

const HEX = '0123456789abcdef';

function HashReveal({ value, active }: { value: string; active: boolean }) {
  const [text, setText] = useState(value);
  const frame = useRef(0);
  useEffect(() => {
    if (!active || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setText(value);
      return undefined;
    }
    const start = performance.now();
    const duration = 1400;
    const step = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      const settled = Math.floor(progress * value.length);
      let next = value.slice(0, settled);
      for (let index = settled; index < value.length; index += 1) {
        next += HEX[Math.floor(Math.random() * 16)];
      }
      setText(next);
      if (progress < 1) frame.current = requestAnimationFrame(step);
    };
    frame.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame.current);
  }, [active, value]);
  return <>{text}</>;
}

/* 10. Record: the chain sealed into one event with a deterministic ID. */
export function RecordScene({ active, eventId }: SceneProps & { eventId: string | null }) {
  const hash = eventId ? eventId.replace(/^security-event:/, '') : null;
  const rows = [
    ['Flow', `${ATTACK.source} → ${ATTACK.target} TCP`],
    ['Window', '5 seconds'],
    ['Detections', 'Port Scan, SYN Flood'],
    ['Risk', '95, critical'],
    ['Policy', 'Alert only'],
    ['Response', 'No action'],
  ];
  return (
    <Scene name="record" active={active}>
      <div className="sc-event">
        <p className="sc-event__head" style={d(0)}>
          <Icon name="record" size={18} />
          Security event
        </p>
        <dl className="sc-event__rows">
          {rows.map(([key, value], index) => (
            <div key={key} style={d(0.1 + index * 0.08)}>
              <dt>{key}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
        <div className="sc-event__hash" style={d(0.7)}>
          <span>
            <Icon name="hash" size={14} /> SHA-256 of flow key and window
          </span>
          <code>{hash ? <HashReveal value={hash} active={active} /> : 'Computed when the event is stored'}</code>
        </div>
      </div>
      <p className="sc-note" style={d(1)}>
        <Icon name="code" size={16} />
        Stored in SQLite, served at <code>GET /events/{'{id}'}</code>
      </p>
    </Scene>
  );
}
