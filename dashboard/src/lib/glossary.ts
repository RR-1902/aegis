import type { IconName } from '../components/Icon';

export type GlossaryEntry = {
  id: string;
  term: string;
  icon: IconName;
  /** One sentence, shown in the inline tooltip. */
  short: string;
  /** What it means in AEGIS specifically, shown in the glossary. */
  inAegis: string;
  group: 'Traffic' | 'Detection' | 'Decision' | 'Record';
};

export const GLOSSARY: GlossaryEntry[] = [
  {
    id: 'packet',
    term: 'Packet',
    icon: 'packet',
    group: 'Traffic',
    short: 'The smallest unit of network traffic: a block of data wrapped in headers that say where it came from and where it is going.',
    inAegis: 'Every packet AEGIS captures becomes a typed record with addresses, ports, TCP flags, size and a timestamp.',
  },
  {
    id: 'header',
    term: 'Header',
    icon: 'layers',
    group: 'Traffic',
    short: 'The labelled fields at the front of a packet. Each protocol layer, such as Ethernet, IP and TCP, adds its own.',
    inAegis: 'The parser reads Ethernet, IPv4 or IPv6, and TCP, UDP or ICMP headers. Payloads are never read or stored.',
  },
  {
    id: 'bpf',
    term: 'BPF filter',
    icon: 'filter',
    group: 'Traffic',
    short: 'A Berkeley Packet Filter expression that tells the capture driver which packets to hand over, such as "tcp or udp".',
    inAegis: 'The default filter is tcp or udp, set by CAPTURE_FILTER. Anything it excludes, ICMP included, never reaches AEGIS.',
  },
  {
    id: 'flow',
    term: 'Flow',
    icon: 'flow',
    group: 'Traffic',
    short: 'All the packets that share the same flow key: the same conversation between two endpoints.',
    inAegis: 'Flows are the unit AEGIS measures. Every feature, detection and event belongs to exactly one flow.',
  },
  {
    id: 'five-tuple',
    term: 'Five-tuple',
    icon: 'key',
    group: 'Traffic',
    short: 'A flow key made of five fields: source IP, destination IP, protocol, source port and destination port.',
    inAegis: 'The runtime default. Because every port pair is its own flow, a scan across many ports is split apart.',
  },
  {
    id: 'three-tuple',
    term: 'Three-tuple',
    icon: 'key',
    group: 'Traffic',
    short: 'A flow key of source IP, destination IP and protocol only, so all ports between two hosts share one flow.',
    inAegis: 'The key that lets the port-scan rule see a scan: one attacker probing many ports becomes a single flow.',
  },
  {
    id: 'window',
    term: 'Time window',
    icon: 'window',
    group: 'Traffic',
    short: 'A fixed slice of time. Packets are counted per window so that rates and ratios can be measured.',
    inAegis: 'Windows are five seconds long and aligned to the clock. A window is summarised once, after it closes.',
  },
  {
    id: 'feature',
    term: 'Feature',
    icon: 'features',
    group: 'Detection',
    short: 'A number that describes a flow in one window, such as how many SYN packets it sent per second.',
    inAegis: 'AEGIS computes 28 features per flow per window. The rules read three of them.',
  },
  {
    id: 'syn',
    term: 'SYN',
    icon: 'syn',
    group: 'Detection',
    short: 'The first packet of a TCP connection. A normal connection continues SYN, SYN-ACK, ACK; an attack often stops after SYN.',
    inAegis: 'A SYN without ACK counts as a connection attempt. Attempts without a matching FIN count as incomplete.',
  },
  {
    id: 'syn-flood',
    term: 'SYN flood',
    icon: 'flood',
    group: 'Detection',
    short: 'A denial-of-service attack that sends SYN packets faster than a server can handle and never completes the handshake.',
    inAegis: 'Fires when syn_rate is at least 10 per second and incomplete_connection_ratio is at least 0.7 in one window.',
  },
  {
    id: 'port-scan',
    term: 'Port scan',
    icon: 'scan',
    group: 'Detection',
    short: 'Reconnaissance that probes many ports on a host to find which services are listening.',
    inAegis: 'Fires when one flow touches at least 20 unique destination ports in one window.',
  },
  {
    id: 'threshold',
    term: 'Threshold',
    icon: 'threshold',
    group: 'Detection',
    short: 'The value a feature must reach before a rule fires. Thresholds are configuration, not learned.',
    inAegis: 'Set in app/config/settings.py or environment variables. Each detection stores the thresholds it was judged against.',
  },
  {
    id: 'rule',
    term: 'Detection rule',
    icon: 'detect',
    group: 'Detection',
    short: 'A fixed test over features. Given the same window it always gives the same answer.',
    inAegis: 'Two rules ship today, SYN Flood and Port Scan. Each records its feature values and comparisons as evidence.',
  },
  {
    id: 'severity',
    term: 'Severity',
    icon: 'severity',
    group: 'Detection',
    short: 'How strongly a single rule fired: medium when a value sits on its threshold, high when it clears it.',
    inAegis: 'Severity decides how many points the detection adds to the risk score.',
  },
  {
    id: 'evidence',
    term: 'Evidence',
    icon: 'evidence',
    group: 'Detection',
    short: 'The exact values, thresholds and comparisons that made a rule fire, saved with the alert.',
    inAegis: 'Anyone can re-check an alert by reading its evidence. Nothing is a hidden weight or a probability.',
  },
  {
    id: 'risk-score',
    term: 'Risk score',
    icon: 'score',
    group: 'Decision',
    short: 'A 0 to 100 number made by adding fixed points for each rule that fired in the same window.',
    inAegis: 'Port scan adds 25 or 40, SYN flood adds 35 or 55, capped at 100. It is a heuristic, not a probability.',
  },
  {
    id: 'risk-level',
    term: 'Risk level',
    icon: 'level',
    group: 'Decision',
    short: 'The score mapped to a band: low 0 to 29, medium 30 to 59, high 60 to 79, critical 80 to 100.',
    inAegis: 'The level, not the raw score, is what the policy engine reads.',
  },
  {
    id: 'policy',
    term: 'Policy',
    icon: 'policy',
    group: 'Decision',
    short: 'The rule book that turns a risk level into a recommended action: log only, alert only, or block source.',
    inAegis: 'Conservative by design: blocking is only recommended for high or critical risk with an attributable source.',
  },
  {
    id: 'observed-source',
    term: 'Observed source',
    icon: 'source',
    group: 'Decision',
    short: 'An address that the evidence itself proves sent the traffic, rather than one inferred from a flow key.',
    inAegis: 'Required before any block. The current rules do not attach one yet, so live traffic never triggers a block.',
  },
  {
    id: 'safe-mode',
    term: 'SAFE_MODE',
    icon: 'lock',
    group: 'Decision',
    short: 'A switch that keeps every response simulated. It is on by default.',
    inAegis: 'With it on, a block is simulated. With it off, the response engine rejects the block, because no executor exists.',
  },
  {
    id: 'simulated',
    term: 'Simulated response',
    icon: 'simulate',
    group: 'Decision',
    short: 'A response that is validated and recorded as if it ran, without touching any firewall or system.',
    inAegis: 'AEGIS never runs a firewall command. Outcomes are no action, simulated or rejected.',
  },
  {
    id: 'security-event',
    term: 'Security event',
    icon: 'record',
    group: 'Record',
    short: 'The permanent record of one alert: flow, window, detections, risk, policy and response together.',
    inAegis: 'Events are immutable and validated before storage. A conflicting duplicate is refused, never overwritten.',
  },
  {
    id: 'sha-256',
    term: 'SHA-256 event ID',
    icon: 'hash',
    group: 'Record',
    short: 'A 64-character fingerprint computed from the flow key and window. The same input always gives the same ID.',
    inAegis: 'Re-running AEGIS on the same traffic produces the same IDs, so a stored event can always be checked.',
  },
  {
    id: 'ledger',
    term: 'Event ledger',
    icon: 'ledger',
    group: 'Record',
    short: 'The list of stored security events, newest first, kept in a SQLite database.',
    inAegis: 'The console on this site reads the ledger through the REST API.',
  },
  {
    id: 'rest-api',
    term: 'REST API',
    icon: 'code',
    group: 'Record',
    short: 'A web interface that returns data as JSON over HTTP.',
    inAegis: 'Read only: GET /health, GET /events and GET /events/{id}. It cannot change or delete events.',
  },
];

export const GLOSSARY_BY_ID: Record<string, GlossaryEntry> = Object.fromEntries(
  GLOSSARY.map((entry) => [entry.id, entry]),
);
