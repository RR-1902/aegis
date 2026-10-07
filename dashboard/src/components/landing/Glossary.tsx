import { useState } from 'react';
import { GLOSSARY, type GlossaryEntry } from '../../lib/glossary';
import Icon from '../Icon';
import SectionHead from './SectionHead';

const GROUPS: (GlossaryEntry['group'] | 'All')[] = ['All', 'Traffic', 'Detection', 'Decision', 'Record'];

export default function Glossary() {
  const [group, setGroup] = useState<(typeof GROUPS)[number]>('All');
  const [expanded, setExpanded] = useState(false);
  const filtered = group === 'All' ? GLOSSARY : GLOSSARY.filter((entry) => entry.group === group);
  const collapsed = group === 'All' && !expanded;
  const entries = collapsed ? filtered.slice(0, 9) : filtered;

  return (
    <section className="section glossary" id="glossary" aria-labelledby="glossary-title">
      <SectionHead id="glossary-title" label="Glossary" icon="explain" title="Every term, in plain words">
        <p>
          Hover over or tap any underlined term on this page for a short definition. Here is the full list, with
          what each one means inside AEGIS.
        </p>
      </SectionHead>

      <div className="glossary__filters" role="group" aria-label="Filter terms" data-reveal="">
        {GROUPS.map((name) => (
          <button
            type="button"
            key={name}
            className="filter-chip"
            aria-pressed={group === name}
            onClick={() => setGroup(name)}
          >
            {name}
            <span className="filter-chip__count">
              {name === 'All' ? GLOSSARY.length : GLOSSARY.filter((entry) => entry.group === name).length}
            </span>
          </button>
        ))}
      </div>

      <ul className="glossary__grid" key={group}>
        {entries.map((entry, index) => (
          <li className="gloss" key={entry.id} id={`term-${entry.id}`} style={{ animationDelay: `${Math.min(index, 12) * 30}ms` }}>
            <span className="gloss__icon">
              <Icon name={entry.icon} size={22} />
            </span>
            <div>
              <h3 className="gloss__term">
                {entry.term}
                <span className="gloss__group">{entry.group}</span>
              </h3>
              <p className="gloss__short">{entry.short}</p>
              <p className="gloss__aegis">
                <span>In AEGIS</span>
                {entry.inAegis}
              </p>
            </div>
          </li>
        ))}
      </ul>
      {collapsed && (
        <div className="glossary__more">
          <button type="button" className="button" onClick={() => setExpanded(true)}>
            Show all {GLOSSARY.length} terms
          </button>
        </div>
      )}
    </section>
  );
}
