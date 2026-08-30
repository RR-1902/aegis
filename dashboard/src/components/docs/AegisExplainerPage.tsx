import React, { useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type Props = {
  onBackToLanding: () => void;
  onLaunchConsole: () => void;
};

export const AegisExplainerPage: React.FC<Props> = ({ onBackToLanding, onLaunchConsole }) => {
  const [activeTab, setActiveTab] = useState<'idrs_basics' | 'what_is_aegis' | 'showcase_goals' | 'simulation_meaning'>('idrs_basics');

  const handleTabChange = (tab: 'idrs_basics' | 'what_is_aegis' | 'showcase_goals' | 'simulation_meaning') => {
    soundFx.playKeyClick();
    setActiveTab(tab);
  };

  return (
    <div className="landing-container" style={{ paddingBottom: 80 }}>
      {/* Top Header Banner */}
      <div className="section-wrapper" style={{ paddingTop: 40, paddingBottom: 30 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <span className="section-index">00 // KNOWLEDGE BASE &amp; ARCHITECTURAL SPECIFICATION</span>
            <h1 className="section-heading">UNDERSTANDING AEGIS &amp; NETWORK INTRUSION DEFENSE</h1>
            <p className="section-subtext">
              An exhaustive academic and practical guide to Intrusion Detection and Response Systems (IDRS), protocol mechanics, deterministic scoring, and safety-gated simulation.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 10 }}>
            <button
              type="button"
              className="btn-cyber-outline"
              onClick={() => { soundFx.playKeyClick(); onBackToLanding(); }}
            >
              <span>← PRODUCT OVERVIEW</span>
            </button>
            <button
              type="button"
              className="btn-cyber-primary"
              onClick={() => { soundFx.playSuccessTone(); onLaunchConsole(); }}
            >
              <span>OPERATIONS CONSOLE ➔</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div style={{
          display: 'flex',
          gap: 10,
          flexWrap: 'wrap',
          marginTop: 32,
          borderBottom: '1px solid var(--border-hairline)',
          paddingBottom: 12
        }}>
          {[
            { id: 'idrs_basics', num: '01', title: 'BASICS OF IDRS' },
            { id: 'what_is_aegis', num: '02', title: 'WHAT IS AEGIS?' },
            { id: 'showcase_goals', num: '03', title: 'WHAT WE SHOWCASE' },
            { id: 'simulation_meaning', num: '04', title: 'THE SIMULATION & CAUSAL CHAIN' },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                className={`btn-toggle ${isActive ? 'active' : ''}`}
                style={{
                  padding: '8px 16px',
                  fontSize: 12,
                  fontWeight: 700,
                  borderColor: isActive ? 'var(--terminal-green)' : 'var(--border-hairline)'
                }}
                onClick={() => handleTabChange(tab.id as typeof activeTab)}
              >
                <span style={{ color: 'var(--terminal-green)', marginRight: 6 }}>{tab.num}//</span>
                <span>{tab.title}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Tab Content */}
      <main className="section-wrapper" style={{ paddingTop: 0 }}>
        {/* ========================================================================= */}
        {/* TAB 1: BASICS OF IDRS */}
        {/* ========================================================================= */}
        {activeTab === 'idrs_basics' && (
          <div className="swiss-box" style={{ padding: 32, background: 'var(--bg-surface)' }}>
            <span style={{ color: 'var(--terminal-green)', fontSize: 11, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
              SECTION 01 // FOUNDATIONS
            </span>
            <h2 style={{ fontSize: '2rem', color: '#ffffff', marginTop: 4, marginBottom: 16 }}>
              What is an Intrusion Detection &amp; Response System (IDRS)?
            </h2>

            <div style={{ color: 'var(--text-muted)', fontSize: 13, lineHeight: 1.8, marginBottom: 24 }}>
              <p style={{ marginBottom: 16 }}>
                Every second, thousands of raw Ethernet frames and IP datagrams traverse network interface cards (NICs). While standard routers merely forward packets according to destination routing tables, an <strong>Intrusion Detection and Response System (IDRS)</strong> acts as an intelligent, vigilant cyber sentry. It inspects packet headers, tracks protocol states across time windows, identifies malicious anomalies, and initiates automated countermeasures.
              </p>
            </div>

            {/* Comparison Grid: IDS vs IPS vs IDRS */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: 16,
              marginBottom: 32
            }}>
              <div style={{ background: 'var(--bg-void)', border: '1px solid var(--border-hairline)', padding: 20 }}>
                <div style={{ color: 'var(--terminal-cyan)', fontSize: 11, textTransform: 'uppercase', marginBottom: 4 }}>
                  01 // PASSIVE IDS
                </div>
                <h3 style={{ color: '#ffffff', fontSize: '1.1rem', marginBottom: 8 }}>Intrusion Detection System</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.6 }}>
                  Listens passively on a SPAN/mirror port. Analyzes traffic out-of-band. Generates log entries and alerts for security analysts but <em>never interferes</em> with traffic.
                </p>
              </div>

              <div style={{ background: 'var(--bg-void)', border: '1px solid var(--border-hairline)', padding: 20 }}>
                <div style={{ color: 'var(--terminal-amber)', fontSize: 11, textTransform: 'uppercase', marginBottom: 4 }}>
                  02 // INLINE IPS
                </div>
                <h3 style={{ color: '#ffffff', fontSize: '1.1rem', marginBottom: 8 }}>Intrusion Prevention System</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.6 }}>
                  Sits inline as a gateway bridge. Drops malicious packets directly in the data path. High risk: a false positive can sever legitimate business communication.
                </p>
              </div>

              <div style={{ background: 'var(--bg-void)', border: '1px solid var(--terminal-green)', padding: 20 }}>
                <div style={{ color: 'var(--terminal-green)', fontSize: 11, textTransform: 'uppercase', marginBottom: 4 }}>
                  03 // HYBRID IDRS (AEGIS MODEL)
                </div>
                <h3 style={{ color: '#ffffff', fontSize: '1.1rem', marginBottom: 8 }}>Detection &amp; Controlled Response</h3>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.6 }}>
                  Captures traffic with zero-copy BPF buffers, extracts stateful 5-tuple flow metrics, scores multi-factor risk, and executes policy-governed mitigations with safety-gated simulation rails.
                </p>
              </div>
            </div>

            {/* Core Concepts */}
            <h3 style={{ color: '#ffffff', fontSize: '1.3rem', marginBottom: 12 }}>Core Networking Primitives in IDRS</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ padding: 16, background: '#070a0e', border: '1px solid var(--border-hairline)' }}>
                <strong style={{ color: 'var(--terminal-green)', fontSize: 13 }}>• Packet-Level vs. Flow-Level Inspection</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4, lineHeight: 1.6 }}>
                  Individual packets rarely reveal an attack. For instance, a single TCP SYN packet is completely normal; however, 5,000 SYN packets with 0 ACKs in a 3-second window constitutes an aggressive SYN Flood. Flow-level inspection aggregates packets into stateful conversations.
                </p>
              </div>

              <div style={{ padding: 16, background: '#070a0e', border: '1px solid var(--border-hairline)' }}>
                <strong style={{ color: 'var(--terminal-cyan)', fontSize: 13 }}>• The 5-Tuple Conversation Key</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4, lineHeight: 1.6 }}>
                  Network streams are indexed by a canonical 5-tuple: <code>(Source IP, Destination IP, Protocol, Source Port, Destination Port)</code>. AEGIS normalizes bi-directional traffic to ensure client-to-server and server-to-client packets map to the same stateful flow record.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 2: WHAT IS AEGIS? */}
        {/* ========================================================================= */}
        {activeTab === 'what_is_aegis' && (
          <div className="swiss-box" style={{ padding: 32, background: 'var(--bg-surface)' }}>
            <span style={{ color: 'var(--terminal-green)', fontSize: 11, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
              SECTION 02 // SYSTEM ARCHITECTURE
            </span>
            <h2 style={{ fontSize: '2rem', color: '#ffffff', marginTop: 4, marginBottom: 16 }}>
              What is AEGIS?
            </h2>

            <p style={{ color: 'var(--text-muted)', fontSize: 13, lineHeight: 1.8, marginBottom: 24 }}>
              <strong>AEGIS</strong> is an academic-grade, genuinely functional <strong>Network Intrusion Detection &amp; Response System</strong> designed for Computer Networks and Cybersecurity education and research. It bridges the gap between theoretical textbook protocol models and real-world raw socket packet parsing, stateful flow tracking, and automated containment.
            </p>

            {/* Visual ASCII Architecture Flowchart */}
            <div style={{ marginBottom: 28 }}>
              <div style={{ color: 'var(--text-dim)', fontSize: 11, textTransform: 'uppercase', marginBottom: 6 }}>
                AEGIS RUNTIME DATAFLOW PIPELINE
              </div>
              <pre className="code-block" style={{ color: 'var(--terminal-green)', fontSize: 12, lineHeight: 1.5, padding: 18 }}>
{`[ PHYSICAL NETWORK INTERFACE (eth0 / Npcap / libpcap) ]
                     │ (AF_PACKET / Raw Socket + BPF Filter)
                     ▼
       ┌─────────────────────────────┐
       │   01. PROTOCOL PARSER       │  --> L2 Ethernet, L3 IPv4, L4 TCP/UDP/ICMP
       └─────────────┬───────────────┘
                     │ (ParsedPacket Data Models)
                     ▼
       ┌─────────────────────────────┐
       │   02. STATEFUL FLOW BUILDER │  --> 5-Tuple Canonical Key, Sliding Windows
       └─────────────┬───────────────┘
                     │ (Finalized FeatureObservation Records)
                     ▼
       ┌─────────────────────────────┐
       │   03. DETERMINISTIC RULES   │  --> SYN Flood, Port Scan, ICMP Storm Signatures
       └─────────────┬───────────────┘
                     │ (DetectionResult Objects)
                     ▼
       ┌─────────────────────────────┐
       │   04. HEURISTIC RISK SCORER │  --> Multi-Factor Severity Matrix (0 - 100)
       └─────────────┬───────────────┘
                     │ (RiskAssessment Scores)
                     ▼
       ┌─────────────────────────────┐
       │   05. POLICY ENGINE         │  --> Safety Rails (BLOCK_SOURCE / ALERT / LOG)
       └─────────────┬───────────────┘
                     │ (ResponseDecision Directives)
                     ▼
       ┌─────────────────────────────┐
       │   06. SIMULATION & LEDGER   │  --> SQLite WAL Mode + FastAPI REST Feed
       └─────────────────────────────┘`}
              </pre>
            </div>

            {/* Distinctive Architectural Pillars */}
            <h3 style={{ color: '#ffffff', fontSize: '1.3rem', marginBottom: 12 }}>Key Architectural Pillars</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              <div style={{ padding: 16, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <strong style={{ color: '#ffffff', fontSize: 13 }}>1. Strict RFC Conformance</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4, lineHeight: 1.6 }}>
                  Parses bit-level headers strictly according to RFC 791 (IPv4), RFC 793 (TCP), RFC 768 (UDP), and RFC 792 (ICMP), with type-safe Pydantic serialization.
                </p>
              </div>

              <div style={{ padding: 16, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <strong style={{ color: '#ffffff', fontSize: 13 }}>2. Bounded Memory Mechanics</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4, lineHeight: 1.6 }}>
                  Flow aggregators utilize pre-allocated ring buffers with strict expiration timeouts (60s) to prevent memory exhaustion during denial-of-service packet floods.
                </p>
              </div>

              <div style={{ padding: 16, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <strong style={{ color: '#ffffff', fontSize: 13 }}>3. Explainable Heuristic Vectors</strong>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 4, lineHeight: 1.6 }}>
                  Every security detection includes structured evidence metadata (e.g. <code>syn_rate: 182.4 pkts/s</code>) so human analysts can verify why a rule was triggered.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 3: WHAT ARE WE TRYING TO SHOWCASE? */}
        {/* ========================================================================= */}
        {activeTab === 'showcase_goals' && (
          <div className="swiss-box" style={{ padding: 32, background: 'var(--bg-surface)' }}>
            <span style={{ color: 'var(--terminal-green)', fontSize: 11, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
              SECTION 03 // EDUCATIONAL &amp; RESEARCH GOALS
            </span>
            <h2 style={{ fontSize: '2rem', color: '#ffffff', marginTop: 4, marginBottom: 16 }}>
              What are we Trying to Showcase?
            </h2>

            <p style={{ color: 'var(--text-muted)', fontSize: 13, lineHeight: 1.8, marginBottom: 24 }}>
              AEGIS was built to demonstrate complete mastery of foundational networking, operating system socket primitives, and defensive cyber-security engineering:
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Point 1 */}
              <div style={{ padding: 20, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ color: 'var(--terminal-green)', fontFamily: 'var(--font-pixel)', fontSize: 12 }}>GOAL_01</span>
                  <h3 style={{ color: '#ffffff', fontSize: '1.2rem' }}>How Real Network Attacks Exploit TCP/IP Mechanics</h3>
                </div>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.7 }}>
                  • <strong>The TCP 3-Way Handshake Vulnerability</strong>: Normal TCP connections require <code>SYN ➔ SYN-ACK ➔ ACK</code>. A SYN Flood floods the target with SYN packets from spoofed IPs, filling the server's Transmission Control Block (TCB) half-open connection backlog queue until legitimate users are locked out.<br />
                  • <strong>Stealth Port Scans (Nmap -sS)</strong>: Scanners send SYN packets across hundreds of ports. If a port replies with <code>SYN-ACK</code>, the port is open; the scanner immediately sends a <code>RST</code> to tear down the connection without completing the handshake to evade basic logging. AEGIS detects these rapid multi-port probes across sliding time windows.
                </p>
              </div>

              {/* Point 2 */}
              <div style={{ padding: 20, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ color: 'var(--terminal-cyan)', fontFamily: 'var(--font-pixel)', fontSize: 12 }}>GOAL_02</span>
                  <h3 style={{ color: '#ffffff', fontSize: '1.2rem' }}>Real-Time Flow Telemetry &amp; Bitfield Dissection</h3>
                </div>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.7 }}>
                  Demonstrating that modern security is not magic—it is binary arithmetic. By unpacking raw octets into L2 Ethernet MACs, L3 IP TTLs and Checksums, and L4 TCP Flag bitmasks, AEGIS visualizes the exact byte-level evidence that triggers detection rules.
                </p>
              </div>

              {/* Point 3 */}
              <div style={{ padding: 20, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ color: 'var(--terminal-amber)', fontFamily: 'var(--font-pixel)', fontSize: 12 }}>GOAL_03</span>
                  <h3 style={{ color: '#ffffff', fontSize: '1.2rem' }}>End-to-End Autonomous Defensive Pipeline</h3>
                </div>
                <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.7 }}>
                  Connecting raw packet capture all the way through a decoupled REST API and modern reactive web console, demonstrating production-grade microservice architecture, clean domain boundaries, and full asynchronous telemetry feeds.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 4: WHAT DOES THE SIMULATION SAY AND MEAN? */}
        {/* ========================================================================= */}
        {activeTab === 'simulation_meaning' && (
          <div className="swiss-box" style={{ padding: 32, background: 'var(--bg-surface)' }}>
            <span style={{ color: 'var(--terminal-green)', fontSize: 11, letterSpacing: '0.15em', textTransform: 'uppercase' }}>
              SECTION 04 // DEFENSIVE PHILOSOPHY
            </span>
            <h2 style={{ fontSize: '2rem', color: '#ffffff', marginTop: 4, marginBottom: 16 }}>
              What Does the Simulation Say and Mean?
            </h2>

            <div style={{ color: 'var(--text-muted)', fontSize: 13, lineHeight: 1.8, marginBottom: 24 }}>
              <p style={{ marginBottom: 16 }}>
                In production cybersecurity environments, the biggest risk of an automated intrusion prevention system is <strong>accidental self-denial of service (false positive blackholing)</strong>. If an IPS erroneously blocks the default gateway or an internal authentication server, it inflicts more damage than the attacker.
              </p>
            </div>

            {/* Why Simulation-Only? */}
            <div style={{ background: '#070a0e', border: '1px solid var(--terminal-cyan)', padding: 24, marginBottom: 24 }}>
              <div style={{ color: 'var(--terminal-cyan)', fontSize: 11, textTransform: 'uppercase', marginBottom: 4 }}>
                THE AEGIS SAFETY-RAIL PHILOSOPHY
              </div>
              <h3 style={{ color: '#ffffff', fontSize: '1.3rem', marginBottom: 12 }}>
                Why "Simulation-Only" Mode is a Feature, Not a Limitation
              </h3>
              <p style={{ color: '#cbd5e1', fontSize: 12, lineHeight: 1.7, marginBottom: 12 }}>
                AEGIS incorporates a strict <code>safe_mode = True</code> policy engine. When a threat reaches critical severity:
              </p>
              <ul style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.8, paddingLeft: 20 }}>
                <li>The system computes the exact mitigation command (e.g. <code>iptables -A INPUT -s 198.51.100.44 -j DROP</code>).</li>
                <li>The response engine executes the decision in <strong>Simulation Mode</strong>: validating that the policy is syntactically sound, verified against safety allowlists, and formatted into an executable result.</li>
                <li>The complete audit trail is permanently committed to the immutable SQLite event ledger and broadcast via the REST API.</li>
                <li><strong>Result</strong>: Zero risk of network disconnection during classroom demonstrations, unit tests, or research evaluations while demonstrating 100% realistic response outcomes!</li>
              </ul>
            </div>

            {/* The Causal Chain Explained */}
            <h3 style={{ color: '#ffffff', fontSize: '1.3rem', marginBottom: 12 }}>The Causal Chain: Detection ➔ Risk ➔ Policy ➔ Response</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.6, marginBottom: 16 }}>
              Every event in AEGIS maintains an unbroken, traceable causal chain from initial observation to mitigation disposition:
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
              <div style={{ padding: 14, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <span style={{ color: 'var(--terminal-green)', fontSize: 10, textTransform: 'uppercase' }}>STEP 01</span>
                <div style={{ color: '#ffffff', fontWeight: 700, margin: '4px 0' }}>DETECTION</div>
                <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>Deterministic rule identifies anomalous signature and packages raw evidence.</div>
              </div>

              <div style={{ padding: 14, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <span style={{ color: 'var(--terminal-amber)', fontSize: 10, textTransform: 'uppercase' }}>STEP 02</span>
                <div style={{ color: '#ffffff', fontWeight: 700, margin: '4px 0' }}>RISK SCORING</div>
                <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>Normalizes evidence confidence and attack velocity into a score (0–100).</div>
              </div>

              <div style={{ padding: 14, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <span style={{ color: 'var(--terminal-cyan)', fontSize: 10, textTransform: 'uppercase' }}>STEP 03</span>
                <div style={{ color: '#ffffff', fontWeight: 700, margin: '4px 0' }}>POLICY ENGINE</div>
                <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>Evaluates safety rails and recommends action (BLOCK_SOURCE / ALERT / LOG).</div>
              </div>

              <div style={{ padding: 14, background: 'var(--bg-void)', border: '1px solid var(--border-hairline)' }}>
                <span style={{ color: 'var(--terminal-purple)', fontSize: 10, textTransform: 'uppercase' }}>STEP 04</span>
                <div style={{ color: '#ffffff', fontWeight: 700, margin: '4px 0' }}>RESPONSE LEDGER</div>
                <div style={{ color: 'var(--text-dim)', fontSize: 11 }}>Executes simulated outcome and commits immutable record to SQLite.</div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default AegisExplainerPage;
