import { useEffect, useState } from 'react';
import type { AegisApi } from '../lib/useAegisApi';
import Icon from './Icon';
import Mark from './Mark';
import SectionLink from './landing/SectionLink';
import StatusRing, { type RingState } from './StatusRing';

type TopBarProps = {
  page: 'overview' | 'ledger';
  health: AegisApi['health'];
};

const SECTIONS = [
  { href: '#about', label: 'About' },
  { href: '#story', label: 'How it works' },
  { href: '#rules', label: 'Rules' },
  { href: '#rule-lab', label: 'Rule lab' },
  { href: '#simulate', label: 'Simulate' },
  { href: '#glossary', label: 'Glossary' },
];

export function apiState(health: AegisApi['health']): { ring: RingState; label: string } {
  if (health.loading) {
    return { ring: 'waiting', label: health.slow ? 'Waking the API…' : 'Connecting…' };
  }
  if (health.data && health.data.status === 'ok') {
    return { ring: 'ok', label: 'API online' };
  }
  return { ring: 'down', label: 'API offline' };
}

export default function TopBar({ page, health }: TopBarProps) {
  const status = apiState(health);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <header className={scrolled ? 'topbar is-scrolled' : 'topbar'}>
      <div className="topbar__inner">
        <a className="topbar__brand" href="#" aria-label="AEGIS home">
          <Mark size={30} />
          <span className="wordmark">AEGIS</span>
        </a>
        {page === 'overview' && (
          <nav className="topbar__nav" aria-label="Sections">
            {SECTIONS.map((section) => (
              <SectionLink key={section.href} className="topbar__link" href={section.href}>
                {section.label}
              </SectionLink>
            ))}
          </nav>
        )}
        <div className="topbar__end">
          <p className="topbar__status" role="status" aria-live="polite" title={status.label}>
            <StatusRing state={status.ring} />
            <span className="topbar__status-label">{status.label}</span>
          </p>
          {page === 'overview' ? (
            <a className="button button--primary button--small" href="#/ledger">
              <Icon name="ledger" size={16} />
              Console
            </a>
          ) : (
            <a className="button button--small" href="#">
              <Icon name="shield" size={16} />
              Overview
            </a>
          )}
        </div>
      </div>
    </header>
  );
}
