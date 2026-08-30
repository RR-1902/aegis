import React from 'react';
import { soundFx } from '../../utils/soundFx';

type Props = {
  onLaunchConsole: () => void;
};

export const SpecsArchitectureSection: React.FC<Props> = ({ onLaunchConsole }) => {
  return (
    <section className="section-wrapper" id="specs-section">
      <div className="section-header">
        <span className="section-index">05 // TECHNICAL BENCHMARKS</span>
        <h2 className="section-heading">ARCHITECTURAL SPECIFICATIONS &amp; LIMITS</h2>
        <p className="section-subtext">
          Engineered for high-density packet throughput, deterministic timing bounds, and minimal memory footprint.
        </p>
      </div>

      {/* 4-Cell Swiss Grid */}
      <div className="specs-grid">
        <div className="spec-cell">
          <div className="spec-label">PACKET PARSE LATENCY</div>
          <div className="spec-value">&lt; 18.4 µs</div>
          <div className="spec-note">✓ Bitmask L2–L4 unpacker</div>
        </div>

        <div className="spec-cell">
          <div className="spec-label">MAX FLOW CAPACITY</div>
          <div className="spec-value">65,536</div>
          <div className="spec-note">✓ Ring buffer bucket capacity</div>
        </div>

        <div className="spec-cell">
          <div className="spec-label">ZERO-LOSS BUFFERING</div>
          <div className="spec-value">64 MB</div>
          <div className="spec-note">✓ Kernel AF_PACKET ring</div>
        </div>

        <div className="spec-cell">
          <div className="spec-label">PERSISTENCE SPEED</div>
          <div className="spec-value">&lt; 1.2 ms</div>
          <div className="spec-note">✓ SQLite WAL batch commits</div>
        </div>
      </div>

      {/* Heuristic Weight Matrix Table */}
      <div className="swiss-box" style={{ marginTop: 32, padding: 24, background: 'var(--bg-surface)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <span style={{ color: 'var(--terminal-green)', fontSize: 11, textTransform: 'uppercase' }}>
            HEURISTIC RISK MATRIX &amp; SEVERITY COEFFICIENTS
          </span>
          <span style={{ color: 'var(--terminal-cyan)', fontSize: 11 }}>NORM: 0.00 – 100.00</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>Attack Vector / Threat Pattern</th>
                <th>Trigger Condition</th>
                <th>Base Weight</th>
                <th>Velocity Multiplier</th>
                <th>Assigned Tier</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="mono" style={{ color: '#ffffff' }}>SYN Flood (DoS Probe)</td>
                <td className="mono">syn_rate &gt; 50/s &amp; syn_ratio &gt; 0.85</td>
                <td className="mono">85.0 pts</td>
                <td className="mono">1.25x / 100pkts</td>
                <td><span className="badge badge-critical">Critical (90+)</span></td>
              </tr>
              <tr>
                <td className="mono" style={{ color: '#ffffff' }}>Horizontal Port Scan</td>
                <td className="mono">unique_dst_ips &gt; 10 in 1.0s</td>
                <td className="mono">70.0 pts</td>
                <td className="mono">1.15x / 10 targets</td>
                <td><span className="badge badge-high">High (70-89)</span></td>
              </tr>
              <tr>
                <td className="mono" style={{ color: '#ffffff' }}>Vertical Port Scan (Nmap)</td>
                <td className="mono">unique_dports &gt; 15 in 2.0s</td>
                <td className="mono">75.0 pts</td>
                <td className="mono">1.20x / 20 ports</td>
                <td><span className="badge badge-high">High (70-89)</span></td>
              </tr>
              <tr>
                <td className="mono" style={{ color: '#ffffff' }}>ICMP Smurf Broadcast Bomb</td>
                <td className="mono">icmp_rate &gt; 100/s &amp; echo_req</td>
                <td className="mono">60.0 pts</td>
                <td className="mono">1.10x</td>
                <td><span className="badge badge-medium">Medium (40-69)</span></td>
              </tr>
              <tr>
                <td className="mono" style={{ color: '#ffffff' }}>RST Abort Anomaly</td>
                <td className="mono">rst_ratio &gt; 0.50 &amp; total &gt; 30</td>
                <td className="mono">45.0 pts</td>
                <td className="mono">1.05x</td>
                <td><span className="badge badge-medium">Medium (40-69)</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Terminal Footer Banner */}
      <footer className="landing-footer">
        <div className="footer-ascii">
{`   ___     ______   _____   ___   ____ 
  / _ \\   / ____/  / ___/  /   | / __ \\
 / /_\\ \\ / __/    / (_ /  / /| | \\ \\/ /
/ /   \\// /___   / /___  / ___ |  \\  / 
\\/     /_____/   \\____/ /_/  |_|  _\\/  
[NETWORK INTRUSION DETECTION & RESPONSE GRID]`}
        </div>

        <div className="footer-bottom-bar">
          <div>
            <span>AEGIS DEFENSIVE GRID · ACADEMIC &amp; PRODUCTION NIDS ARCHITECTURE</span>
          </div>

          <div style={{ display: 'flex', gap: 16 }}>
            <button
              type="button"
              className="btn-cyber-primary"
              onClick={() => { soundFx.playSuccessTone(); onLaunchConsole(); }}
            >
              <span>ACCESS OPERATIONS CONSOLE ➔</span>
            </button>
          </div>
        </div>
      </footer>
    </section>
  );
};

export default SpecsArchitectureSection;
