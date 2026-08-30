import React, { useEffect, useRef, useState } from 'react';
import { soundFx } from '../../utils/soundFx';
import MatrixRainCanvas from './MatrixRainCanvas';

type Props = {
  onLaunchConsole: () => void;
  onExploreSimulator: () => void;
};

const CYPHER_GLYPHS = '0123456789ABCDEF!@#$%&*<>[]{}~+=_-/|\\';

export const HeroSection: React.FC<Props> = ({ onLaunchConsole, onExploreSimulator }) => {
  const [cypherText, setCypherText] = useState('AEGIS // INTRUSION DETECTION & RESPONSE GRID');
  const [packetCount, setPacketCount] = useState(148290);
  const [flowCount, setFlowCount] = useState(3842);
  const [threatCount, setThreatCount] = useState(19);

  // 3D Card Tilt State
  const [tiltStyle, setTiltStyle] = useState<{ transform: string; spotlightX: number; spotlightY: number }>({
    transform: 'perspective(1000px) rotateX(0deg) rotateY(0deg)',
    spotlightX: 50,
    spotlightY: 50,
  });

  const heroRef = useRef<HTMLElement | null>(null);

  // Live packet ticker effect
  useEffect(() => {
    const interval = setInterval(() => {
      setPacketCount((prev) => prev + Math.floor(Math.random() * 45) + 10);
      if (Math.random() > 0.6) {
        setFlowCount((prev) => prev + Math.floor(Math.random() * 3));
      }
      if (Math.random() > 0.95) {
        setThreatCount((prev) => prev + 1);
      }
    }, 400);
    return () => clearInterval(interval);
  }, []);

  // Text scramble cypher effect
  const triggerScramble = (targetText: string) => {
    soundFx.playKeyClick();
    let iteration = 0;
    const interval = setInterval(() => {
      setCypherText(
        targetText
          .split('')
          .map((char, index) => {
            if (index < iteration || char === ' ' || char === '/') return char;
            return CYPHER_GLYPHS[Math.floor(Math.random() * CYPHER_GLYPHS.length)];
          })
          .join('')
      );

      if (iteration >= targetText.length) {
        clearInterval(interval);
      }
      iteration += 1;
    }, 22);
  };

  useEffect(() => {
    triggerScramble('AEGIS // INTRUSION DETECTION & RESPONSE GRID');
  }, []);

  // 3D Tilt calculation on mouse move
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const card = e.currentTarget;
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    const rotateX = ((y - centerY) / centerY) * -7;
    const rotateY = ((x - centerX) / centerX) * 7;

    setTiltStyle({
      transform: `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-4px)`,
      spotlightX: Math.round((x / rect.width) * 100),
      spotlightY: Math.round((y / rect.height) * 100),
    });
  };

  const handleMouseLeave = () => {
    setTiltStyle({
      transform: 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px)',
      spotlightX: 50,
      spotlightY: 50,
    });
  };

  return (
    <section 
      ref={heroRef}
      className="landing-hero bg-grid-pattern" 
      id="hero-section"
      style={{ position: 'relative', overflow: 'hidden' }}
    >
      {/* Interactive Matrix Rain Stream Background Canvas */}
      <MatrixRainCanvas />

      {/* Foreground Content with relative z-index */}
      <div style={{
        position: 'relative',
        zIndex: 2,
        width: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center'
      }}>
        {/* Tactical Status Tag */}
        <div className="hero-tag">
          <span className="status-dot ok" />
          <span>KERNEL DRIVER: SECURE</span>
          <span style={{ color: 'var(--text-dim)' }}>|</span>
          <span>BPF FILTER: ACTIVE</span>
          <span style={{ color: 'var(--text-dim)' }}>|</span>
          <span style={{ color: 'var(--terminal-cyan)' }}>ZERO-COPY PCAP</span>
        </div>

        {/* Cyber Hero Title with Cypher Decryption Subtitle */}
        <div 
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 12,
            letterSpacing: '0.2em',
            color: 'var(--terminal-green)',
            marginBottom: 16,
            textTransform: 'uppercase',
            cursor: 'pointer',
            textAlign: 'center',
            display: 'block'
          }}
          onClick={() => triggerScramble('AEGIS // INTRUSION DETECTION & RESPONSE GRID')}
          title="Click to re-scramble cipher"
        >
          {cypherText}
        </div>

        <h1 
          className="hero-title"
          onMouseEnter={() => triggerScramble('AEGIS // AUTONOMOUS DEFENSE ACTIVE')}
          style={{
            cursor: 'default',
            textAlign: 'center',
            marginLeft: 'auto',
            marginRight: 'auto'
          }}
        >
          REAL-TIME NETWORK <br />
          <span className="glow-green" style={{ textShadow: '0 0 25px rgba(34, 197, 94, 0.6)' }}>
            SURVEILLANCE &amp; DEFENSE
          </span>
        </h1>

        <p className="hero-desc" style={{ marginLeft: 'auto', marginRight: 'auto', textAlign: 'center' }}>
          A deterministic L2–L4 network intrusion detection engine. Engineered with raw socket packet capture, 
          stateful 5-tuple flow aggregation, sub-millisecond heuristic scoring, and automated containment policies.
        </p>

        {/* Hero CTA Action Grid */}
        <div className="hero-actions" style={{ justifyContent: 'center' }}>
          <button
            type="button"
            className="btn-cyber-primary"
            onClick={() => { soundFx.playSuccessTone(); onLaunchConsole(); }}
          >
            <span>⚡ LAUNCH OPS CONSOLE</span>
          </button>

          <button
            type="button"
            className="btn-cyber-outline"
            onClick={() => { soundFx.playKeyClick(); onExploreSimulator(); }}
          >
            <span>🔍 RUN THREAT SIMULATOR</span>
          </button>
        </div>

        {/* Realtime Telemetry Bar */}
        <div style={{
          display: 'flex',
          gap: 20,
          flexWrap: 'wrap',
          justifyContent: 'center',
          marginBottom: 40,
          fontFamily: 'var(--font-mono)',
          fontSize: 12
        }}>
          <div className="swiss-box" style={{ padding: '8px 16px', background: 'rgba(5,7,10,0.85)', backdropFilter: 'blur(8px)' }}>
            <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>PACKETS CAPTURED: </span>
            <span style={{ color: 'var(--terminal-green)', fontWeight: 700 }}>{packetCount.toLocaleString()}</span>
          </div>
          <div className="swiss-box" style={{ padding: '8px 16px', background: 'rgba(5,7,10,0.85)', backdropFilter: 'blur(8px)' }}>
            <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>ACTIVE FLOWS: </span>
            <span style={{ color: 'var(--terminal-cyan)', fontWeight: 700 }}>{flowCount.toLocaleString()}</span>
          </div>
          <div className="swiss-box" style={{ padding: '8px 16px', background: 'rgba(5,7,10,0.85)', backdropFilter: 'blur(8px)' }}>
            <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>MITIGATED ATTACKS: </span>
            <span style={{ color: 'var(--terminal-amber)', fontWeight: 700 }}>{threatCount} DETECTED</span>
          </div>
        </div>

        {/* Hero Terminal & 3D Visual Duo Grid with 3D Tilt & Cursor Spotlight */}
        <div 
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 0.8fr)',
            gap: 20,
            maxWidth: 1280,
            width: '100%',
            margin: '0 auto',
            textAlign: 'left'
          }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        >
          {/* Left: Interactive Hero Terminal with dynamic tilt */}
          <div 
            className="hero-terminal-mock swiss-box" 
            style={{ 
              maxWidth: '100%',
              transform: tiltStyle.transform,
              transition: 'transform 0.15s ease-out, box-shadow 0.2s ease',
              backgroundImage: `radial-gradient(circle at ${tiltStyle.spotlightX}% ${tiltStyle.spotlightY}%, rgba(34, 197, 94, 0.08) 0%, transparent 60%)`,
              boxShadow: '0 12px 30px rgba(0,0,0,0.6)'
            }}
          >
            <div className="terminal-header-bar">
              <div className="terminal-dots">
                <span className="terminal-dot red" />
                <span className="terminal-dot yellow" />
                <span className="terminal-dot green" />
              </div>
              <span style={{ fontFamily: 'var(--font-mono)', letterSpacing: '0.1em' }}>
                root@aegis-core: ~/pipeline#
              </span>
              <span style={{ color: 'var(--terminal-green)', fontSize: 10 }}>● LIVE</span>
            </div>

            <div className="terminal-body">
              <div style={{ color: 'var(--terminal-green)', marginBottom: 8 }}>
                [AEGIS ENGINE DAEMON INITIALIZED]
              </div>
              <div style={{ color: 'var(--text-dim)', marginBottom: 4 }}>
                $ python -m app.capture --interface eth0 --window 5s --strict-rules
              </div>
              <div style={{ color: '#ffffff', marginBottom: 4 }}>
                &gt; Binding AF_PACKET raw socket on device: eth0 (MTU: 1500)
              </div>
              <div style={{ color: '#94a3b8', marginBottom: 4 }}>
                &gt; Compiling BPF filter expression: <span style={{ color: 'var(--terminal-cyan)' }}>"ip and (tcp or udp or icmp)"</span>
              </div>
              <div style={{ color: '#94a3b8', marginBottom: 4 }}>
                &gt; Allocating 5-tuple flow ring buffers: 65,536 buckets initialized (1.4MB)
              </div>
              <div style={{ color: 'var(--terminal-green)', marginTop: 8 }}>
                &gt; Engine Ready. Telemetry stream broadcasting to SQLite &amp; REST /api/v1/events
                <span className="terminal-cursor" style={{ marginLeft: 6 }} />
              </div>
            </div>
          </div>

          {/* Right: 3D Holographic Core Shield Card with dynamic tilt */}
          <div 
            className="swiss-box" 
            style={{
              background: 'var(--bg-surface)',
              padding: 12,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              border: '1px solid var(--border-hairline)',
              transform: tiltStyle.transform,
              transition: 'transform 0.15s ease-out, box-shadow 0.2s ease',
              backgroundImage: `radial-gradient(circle at ${tiltStyle.spotlightX}% ${tiltStyle.spotlightY}%, rgba(6, 182, 212, 0.1) 0%, transparent 65%)`,
              boxShadow: '0 12px 30px rgba(0,0,0,0.6)'
            }}
          >
            <div style={{ position: 'relative', overflow: 'hidden', height: 210, background: '#000000' }}>
              <img
                src="/assets/aegis_core_shield.jpg"
                alt="AEGIS 3D Core Defense Shield"
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  opacity: 0.95,
                  filter: 'contrast(1.1) brightness(1.05)'
                }}
              />
              <div style={{
                position: 'absolute',
                bottom: 8,
                left: 8,
                background: 'rgba(0,0,0,0.8)',
                padding: '3px 8px',
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: 'var(--terminal-green)',
                border: '1px solid rgba(34,197,94,0.3)'
              }}>
                SEC_CORE_v7.3 // ISOMETRIC SHIELD
              </div>
            </div>

            <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
              <span style={{ color: 'var(--text-dim)' }}>ZERO-COPY BUFFERING</span>
              <span style={{ color: 'var(--terminal-cyan)', fontWeight: 700 }}>64MB AF_PACKET</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;

