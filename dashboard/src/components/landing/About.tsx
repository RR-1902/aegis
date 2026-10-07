import Icon, { type IconName } from '../Icon';
import Term from '../Term';
import SectionHead from './SectionHead';

const PILLARS: { icon: IconName; title: string; text: string }[] = [
  {
    icon: 'observe',
    title: 'Observe',
    text: 'Captures packets from a network interface, reads their headers and groups them into flows measured in five-second windows.',
  },
  {
    icon: 'detect',
    title: 'Detect',
    text: 'Checks every window against explicit rules for SYN floods and port scans. No training data, no hidden weights.',
  },
  {
    icon: 'explain',
    title: 'Explain',
    text: 'Keeps the feature values, thresholds and comparisons behind each alert, so anyone can check why it fired.',
  },
  {
    icon: 'simulate',
    title: 'Respond safely',
    text: 'Decides what a proportionate response would be and simulates it. It never touches a firewall or the host.',
  },
];

const FACTS: { value: number; decimals?: number; suffix?: string; label: string; icon: IconName }[] = [
  { value: 10, label: 'pipeline stages, one module each', icon: 'flow' },
  { value: 28, label: 'features measured per flow window', icon: 'features' },
  { value: 2, label: 'detection rules with fixed thresholds', icon: 'detect' },
  { value: 280, label: 'automated backend tests', icon: 'test' },
  { value: 0, label: 'firewall commands ever executed', icon: 'lock' },
];

export default function About() {
  return (
    <section className="section about" id="about" aria-labelledby="about-title">
      <div className="about__intro">
        <SectionHead id="about-title" label="About the project" icon="shield" title="What is AEGIS?">
          <p>
            AEGIS is a network intrusion detection and response system built to be understood. It reads live
            traffic, measures each conversation in short time windows, and tests those measurements against
            explicit rules for two common attacks: <Term id="syn-flood">SYN floods</Term> and{' '}
            <Term id="port-scan">port scans</Term>.
          </p>
          <p>
            When a rule fires, AEGIS scores the risk, decides what a safe response would be, and stores the
            whole chain of reasoning as one permanent <Term id="security-event">security event</Term>. Nothing
            is learned or guessed, so the same traffic always produces the same verdict.
          </p>
        </SectionHead>

        <aside className="origin" data-reveal="">
          <p className="origin__word">aegis</p>
          <p className="origin__phonetic">/ˈiː.dʒɪs/ · Greek, αἰγίς</p>
          <p>
            In Greek myth, the aegis was the shield carried by Zeus and Athena. To act under someone’s aegis
            is to act under their protection.
          </p>
          <p className="muted">
            The system takes the name for what it does: stand between a network and the traffic that targets
            it, and account for every decision it makes.
          </p>
        </aside>
      </div>

      <ul className="pillars">
        {PILLARS.map((pillar, index) => (
          <li className="pillar" key={pillar.title} data-reveal="">
            <span className="pillar__index">0{index + 1}</span>
            <span className="pillar__icon">
              <Icon name={pillar.icon} size={26} />
            </span>
            <h3 className="pillar__title">{pillar.title}</h3>
            <p>{pillar.text}</p>
          </li>
        ))}
      </ul>

      <ul className="facts" aria-label="AEGIS in numbers">
        {FACTS.map((fact) => (
          <li className="fact" key={fact.label} data-reveal="">
            <Icon name={fact.icon} size={18} className="fact__icon" />
            <span className="fact__value" data-count={fact.value} data-decimals={fact.decimals ?? 0}>
              {fact.value}
            </span>
            <span className="fact__label">{fact.label}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
