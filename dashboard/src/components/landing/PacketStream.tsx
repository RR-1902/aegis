import { usePauseOffscreen } from '../../lib/motion';

type Chip = { proto: string; route: string; flag?: string; level?: string };

const LANE_A: Chip[] = [
  { proto: 'TCP', route: '203.0.113.201:50003 → 10.0.0.4:22', flag: 'SYN', level: 'critical' },
  { proto: 'UDP', route: '10.0.0.20:12345 → 10.0.0.53:53' },
  { proto: 'TCP', route: '10.0.0.9:51522 → 10.0.0.4:443', flag: 'ACK' },
  { proto: 'TCP', route: '203.0.113.201:50011 → 10.0.0.4:3389', flag: 'SYN', level: 'critical' },
  { proto: 'TCP', route: '10.0.0.7:60210 → 10.0.0.2:80', flag: 'PSH ACK' },
  { proto: 'UDP', route: '10.0.0.31:5353 → 224.0.0.251:5353' },
];

const LANE_B: Chip[] = [
  { proto: 'TCP', route: '198.51.100.44:54201 → 10.0.0.1:80', flag: 'SYN', level: 'high' },
  { proto: 'TCP', route: '10.0.0.4:22 → 10.0.0.12:40122', flag: 'SYN ACK' },
  { proto: 'UDP', route: '10.0.0.12:41000 → 10.0.0.53:53' },
  { proto: 'TCP', route: '192.0.2.15:40007 → 10.0.0.12:27', flag: 'SYN', level: 'low' },
  { proto: 'TCP', route: '10.0.0.2:443 → 10.0.0.7:60211', flag: 'FIN ACK' },
  { proto: 'TCP', route: '198.51.100.7:50014 → 10.0.0.8:8014', flag: 'SYN', level: 'medium' },
];

function Lane({ chips, reverse = false }: { chips: Chip[]; reverse?: boolean }) {
  // Two copies side by side; the track slides by half its width and loops seamlessly.
  const doubled = [...chips, ...chips];
  return (
    <div className={reverse ? 'stream__lane stream__lane--slow' : 'stream__lane'}>
      <div className="stream__track">
        {doubled.map((chip, index) => (
          <span className="chip" data-level={chip.level} key={index}>
            <span className="chip__proto">{chip.proto}</span>
            <span className="chip__route">{chip.route}</span>
            {chip.flag && <span className="chip__flag">{chip.flag}</span>}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Illustrative traffic passing under the hero. Decorative; the real data lives in the ledger. */
export default function PacketStream() {
  const ref = usePauseOffscreen<HTMLDivElement>();
  return (
    <div className="stream" ref={ref} aria-hidden="true">
      <Lane chips={LANE_A} />
      <Lane chips={LANE_B} reverse />
    </div>
  );
}
