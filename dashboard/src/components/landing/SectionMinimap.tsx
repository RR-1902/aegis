import React, { useEffect, useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type SectionItem = {
  id: string;
  label: string;
  index: string;
};

const SECTIONS: SectionItem[] = [
  { id: 'hero-section', label: 'HERO // CORE', index: '00' },
  { id: 'pipeline-section', label: 'PIPELINE ARCH', index: '01' },
  { id: 'radar-section', label: '3D TOPOLOGY', index: '02' },
  { id: 'simulator-section', label: 'THREAT SANDBOX', index: '03' },
  { id: 'dissector-section', label: 'HEX DISSECTOR', index: '04' },
  { id: 'cli-section', label: 'AEGIS TERMINAL', index: '05' },
  { id: 'specs-section', label: 'SPECS MATRIX', index: '06' },
  { id: 'live-console-grid', label: 'OPS CONSOLE', index: '07' },
];

export const SectionMinimap: React.FC = () => {
  const [activeId, setActiveId] = useState<string>('hero-section');

  useEffect(() => {
    const handleScroll = () => {
      const scrollPos = window.scrollY + window.innerHeight / 3;

      for (let i = SECTIONS.length - 1; i >= 0; i--) {
        const el = document.getElementById(SECTIONS[i].id);
        if (el && el.offsetTop <= scrollPos) {
          setActiveId(SECTIONS[i].id);
          break;
        }
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();

    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  const handleJump = (id: string) => {
    soundFx.playKeyClick();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <aside className="cyber-minimap" aria-label="Section Minimap">
      {SECTIONS.map((sec) => {
        const isActive = activeId === sec.id;
        return (
          <button
            key={sec.id}
            type="button"
            className={`minimap-item ${isActive ? 'active' : ''}`}
            onClick={() => handleJump(sec.id)}
            title={sec.label}
          >
            <span className="minimap-dot" />
            <span className="minimap-label">{sec.index} {sec.label}</span>
          </button>
        );
      })}
    </aside>
  );
};

export default SectionMinimap;
