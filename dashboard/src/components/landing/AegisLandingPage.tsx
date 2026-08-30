import React from 'react';
import HeroSection from './HeroSection';
import PipelineScrollSection from './PipelineScrollSection';
import AttackSimulatorSection from './AttackSimulatorSection';
import PacketDissectorSection from './PacketDissectorSection';
import TerminalCliSection from './TerminalCliSection';
import SpecsArchitectureSection from './SpecsArchitectureSection';
import CyberRadarCanvas from './CyberRadarCanvas';
import CinematicSection from './CinematicSection';
import SectionMinimap from './SectionMinimap';

type Props = {
  onLaunchConsole: () => void;
};

export const AegisLandingPage: React.FC<Props> = ({ onLaunchConsole }) => {
  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="landing-container">
      {/* Right Edge Cyber Minimap */}
      <SectionMinimap />

      {/* Hero Section */}
      <CinematicSection id="hero-section" locatorTag="CORE_INIT // 00">
        <HeroSection
          onLaunchConsole={onLaunchConsole}
          onExploreSimulator={() => scrollToSection('simulator-section')}
        />
      </CinematicSection>

      {/* 6-Stage Detection Pipeline */}
      <CinematicSection id="pipeline-section" locatorTag="PIPELINE_FLOW // 01">
        <PipelineScrollSection />
      </CinematicSection>

      {/* 3D Spatial Network Radar & Topology Visualizer */}
      <CinematicSection id="radar-section" locatorTag="SPATIAL_RADAR // 02" className="section-wrapper">
        <div className="section-header">
          <span className="section-index">02 // SPATIAL SURVEILLANCE</span>
          <h2 className="section-heading">3D NETWORK TOPOLOGY &amp; THREAT VECTOR MAPPING</h2>
          <p className="section-subtext">
            Continuous real-time spatial projection of ingress flows, gateway firewalls, and isolated malicious attack vectors.
          </p>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 0.8fr)',
          gap: 20
        }}>
          {/* Interactive Live 3D Canvas Radar */}
          <CyberRadarCanvas />

          {/* Holographic Network Topology Card */}
          <div className="swiss-box" style={{
            background: 'var(--bg-surface)',
            padding: 20,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            border: '1px solid var(--border-hairline)'
          }}>
            <div style={{ position: 'relative', overflow: 'hidden', height: 260, background: '#000000', marginBottom: 12 }}>
              <img
                src="/assets/aegis_threat_topology.jpg"
                alt="AEGIS Cyber Defense Network Topology"
                style={{
                  width: '100%',
                  height: '100%',
                  objectFit: 'cover',
                  filter: 'contrast(1.15) brightness(1.05)'
                }}
              />
              <div style={{
                position: 'absolute',
                top: 8,
                left: 8,
                background: 'rgba(0,0,0,0.8)',
                padding: '3px 8px',
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: 'var(--terminal-cyan)',
                border: '1px solid rgba(6,182,212,0.4)'
              }}>
                ● TOPOLOGY INGRESS: 2.4 PB/S
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11 }}>
              <div style={{ padding: 10, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <div style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>ISOLATION SPEED</div>
                <div style={{ color: 'var(--terminal-green)', fontWeight: 700, marginTop: 2 }}>&lt; 0.2ms SUB-MS</div>
              </div>
              <div style={{ padding: 10, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <div style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>FIREWALL NODES</div>
                <div style={{ color: 'var(--terminal-cyan)', fontWeight: 700, marginTop: 2 }}>AUTO-REACTIVE</div>
              </div>
            </div>
          </div>
        </div>
      </CinematicSection>

      {/* Interactive Threat Simulator */}
      <CinematicSection id="simulator-section" locatorTag="THREAT_SANDBOX // 03">
        <AttackSimulatorSection />
      </CinematicSection>

      {/* Hex & Protocol Dissector */}
      <CinematicSection id="dissector-section" locatorTag="HEX_DISSECTOR // 04">
        <PacketDissectorSection />
      </CinematicSection>

      {/* Interactive In-Browser CLI Terminal */}
      <CinematicSection id="cli-section" locatorTag="TERMINAL_SHELL // 05">
        <TerminalCliSection />
      </CinematicSection>

      {/* Specs Grid & Risk Matrix */}
      <CinematicSection id="specs-section" locatorTag="BENCHMARKS // 06">
        <SpecsArchitectureSection onLaunchConsole={onLaunchConsole} />
      </CinematicSection>
    </div>
  );
};

export default AegisLandingPage;


