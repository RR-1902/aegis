import Icon, { type IconName } from '../Icon';
import SectionHead from './SectionHead';

const NODES: { icon: IconName; title: string; command: string; text: string }[] = [
  {
    icon: 'capture',
    title: 'Detection runtime',
    command: 'python -m app.main',
    text: 'Captures, parses, groups, measures, detects, scores, decides and responds.',
  },
  {
    icon: 'record',
    title: 'Event ledger',
    command: 'aegis.db',
    text: 'SQLite. Immutable security events, indexed by time.',
  },
  {
    icon: 'code',
    title: 'REST API',
    command: 'uvicorn app.api.main:app',
    text: 'FastAPI, read only: /health, /events, /events/{id}.',
  },
  {
    icon: 'observe',
    title: 'This console',
    command: 'dashboard/',
    text: 'React and TypeScript. Reads the API, never writes.',
  },
];

const STACK: { group: string; items: [string, string][] }[] = [
  {
    group: 'Engine',
    items: [
      ['Python 3.11+', 'Runtime for every pipeline stage'],
      ['Scapy 2.6', 'Packet capture and header parsing'],
      ['Pydantic Settings', 'Thresholds and switches from the environment'],
    ],
  },
  {
    group: 'API and storage',
    items: [
      ['FastAPI', 'Read-only REST endpoints with typed errors'],
      ['SQLite', 'Single-file event ledger, no server needed'],
      ['pytest', '280 tests across 12 suites'],
    ],
  },
  {
    group: 'Interface',
    items: [
      ['React 18 and TypeScript', 'Console, story and rule lab'],
      ['GSAP and Lenis', 'Scroll-driven story and smooth scrolling'],
      ['Vite', 'Builds the static site deployed on Vercel'],
    ],
  },
];

export default function Stack() {
  return (
    <section className="section stack" id="stack" aria-labelledby="stack-title">
      <SectionHead id="stack-title" label="Under the hood" icon="code" title="How AEGIS is built">
        <p>
          Two processes share one database file. The runtime writes events; the API only reads them. Nothing on
          the web side can change what the engine recorded.
        </p>
      </SectionHead>

      <ol className="arch" aria-label="Architecture">
        {NODES.map((node, index) => (
          <li className="arch__node" key={node.title} data-reveal="">
            <span className="arch__icon">
              <Icon name={node.icon} size={22} />
            </span>
            <h3>{node.title}</h3>
            <code>{node.command}</code>
            <p>{node.text}</p>
            {index < NODES.length - 1 && (
              <span className="arch__link" aria-hidden="true">
                <Icon name="arrow" size={16} />
              </span>
            )}
          </li>
        ))}
      </ol>

      <div className="stack__groups">
        {STACK.map((group) => (
          <div className="stack__group" key={group.group} data-reveal="">
            <h3>{group.group}</h3>
            <ul>
              {group.items.map(([name, role]) => (
                <li key={name}>
                  <span>{name}</span>
                  <span className="muted">{role}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
