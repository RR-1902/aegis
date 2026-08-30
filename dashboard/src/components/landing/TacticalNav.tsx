import React, { useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type Props = {
  currentView: 'landing' | 'console' | 'docs';
  onViewChange: (view: 'landing' | 'console' | 'docs') => void;
  scanlinesActive: boolean;
  onToggleScanlines: () => void;
};

export const TacticalNav: React.FC<Props> = ({
  currentView,
  onViewChange,
  scanlinesActive,
  onToggleScanlines,
}) => {
  const [audioActive, setAudioActive] = useState(() => soundFx.isAudioEnabled());

  const handleAudioToggle = () => {
    const next = soundFx.toggleAudio();
    setAudioActive(next);
  };

  const handleNavClick = (sectionId: string) => {
    soundFx.playKeyClick();
    if (currentView !== 'landing') {
      onViewChange('landing');
      setTimeout(() => {
        const el = document.getElementById(sectionId);
        if (el) el.scrollIntoView({ behavior: 'smooth' });
      }, 100);
    } else {
      const el = document.getElementById(sectionId);
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <nav className="tactical-hud" aria-label="Tactical Navigation">
      <div className="tactical-hud-inner">
        {/* Brand */}
        <div 
          className="nav-brand" 
          role="button" 
          tabIndex={0}
          onClick={() => { soundFx.playKeyClick(); onViewChange('landing'); }}
          onKeyDown={(e) => { if (e.key === 'Enter') onViewChange('landing'); }}
          style={{ cursor: 'pointer' }}
        >
          <div className="brand-icon">⬡</div>
          <div>
            <span className="brand-text">AEGIS</span>
            <span className="brand-version" style={{ marginLeft: 8 }}>v2.4-SEC</span>
          </div>
        </div>

        {/* Dynamic Nav Links with Monospace Odometer Aesthetics */}
        <div className="hud-nav-links">
          <button 
            type="button" 
            className={`odometer-link ${currentView === 'docs' ? 'active' : ''}`}
            onClick={() => { soundFx.playKeyClick(); onViewChange('docs'); }}
            style={{ color: currentView === 'docs' ? 'var(--terminal-green)' : undefined }}
          >
            <span style={{ color: 'var(--terminal-cyan)' }}>00//</span>DOCS &amp; EXPLAINER
          </button>
          <button 
            type="button" 
            className="odometer-link"
            onClick={() => handleNavClick('pipeline-section')}
          >
            <span style={{ color: 'var(--terminal-green)' }}>01//</span>PIPELINE
          </button>
          <button 
            type="button" 
            className="odometer-link"
            onClick={() => handleNavClick('simulator-section')}
          >
            <span style={{ color: 'var(--terminal-cyan)' }}>02//</span>SIMULATOR
          </button>
          <button 
            type="button" 
            className="odometer-link"
            onClick={() => handleNavClick('dissector-section')}
          >
            <span style={{ color: 'var(--terminal-amber)' }}>03//</span>DISSECTOR
          </button>
          <button 
            type="button" 
            className="odometer-link"
            onClick={() => handleNavClick('cli-section')}
          >
            <span style={{ color: 'var(--terminal-green)' }}>04//</span>CLI
          </button>
        </div>

        {/* Right Actions / Toggles */}
        <div className="hud-actions">
          {/* Audio FX Toggle */}
          <button
            type="button"
            className={`btn-toggle ${audioActive ? 'active' : ''}`}
            onClick={handleAudioToggle}
            title="Toggle Retro Synthesizer Audio FX"
          >
            <span>{audioActive ? '🔊 FX:ON' : '🔇 FX:OFF'}</span>
          </button>

          {/* CRT Scanline Toggle */}
          <button
            type="button"
            className={`btn-toggle ${scanlinesActive ? 'active' : ''}`}
            onClick={() => { soundFx.playKeyClick(); onToggleScanlines(); }}
            title="Toggle CRT Scanline Shader"
          >
            <span>{scanlinesActive ? '📺 CRT:ON' : '📺 CRT:OFF'}</span>
          </button>

          {/* View Mode Toggle: Landing Page vs Cyber Operations Console */}
          {currentView === 'landing' ? (
            <button
              type="button"
              className="btn-cyber-primary"
              onClick={() => { soundFx.playSuccessTone(); onViewChange('console'); }}
            >
              <span>OPERATIONS CONSOLE ➔</span>
            </button>
          ) : (
            <button
              type="button"
              className="btn-cyber-outline"
              onClick={() => { soundFx.playKeyClick(); onViewChange('landing'); }}
            >
              <span>← PRODUCT OVERVIEW</span>
            </button>
          )}
        </div>
      </div>
    </nav>
  );
};

export default TacticalNav;
