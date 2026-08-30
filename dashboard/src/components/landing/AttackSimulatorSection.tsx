import React, { useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type AttackType = 'syn_flood' | 'port_scan' | 'icmp_burst';

type SimulationState = {
  active: boolean;
  type: AttackType;
  step: number;
  packetsSent: number;
  detectedThreat: string | null;
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  mitigationStatus: string;
  logs: string[];
};

export const AttackSimulatorSection: React.FC = () => {
  const [sim, setSim] = useState<SimulationState>({
    active: false,
    type: 'syn_flood',
    step: 0,
    packetsSent: 0,
    detectedThreat: null,
    riskScore: 0,
    riskLevel: 'low',
    mitigationStatus: 'IDLE - READY FOR SIMULATION',
    logs: [
      '[SYSTEM READY] AEGIS detection sandbox armed.',
      'Select an attack vector below to evaluate real-time deterministic detection & mitigation.',
    ],
  });

  const runSimulation = (type: AttackType) => {
    soundFx.playKeyClick();
    setSim({
      active: true,
      type,
      step: 1,
      packetsSent: 0,
      detectedThreat: null,
      riskScore: 10,
      riskLevel: 'low',
      mitigationStatus: 'INJECTING PACKET STREAM...',
      logs: [`[SIM_INIT] Injecting attack vector: ${type.toUpperCase()}`],
    });

    // Step 1: Burst Packets
    setTimeout(() => {
      soundFx.playKeyClick();
      setSim((prev) => ({
        ...prev,
        step: 2,
        packetsSent: type === 'syn_flood' ? 840 : type === 'port_scan' ? 120 : 500,
        riskScore: 45,
        riskLevel: 'medium',
        mitigationStatus: 'FLOW AGGREGATOR DETECTING ANOMALY...',
        logs: [
          ...prev.logs,
          type === 'syn_flood'
            ? `> Flow Builder: 840 packets observed with SYN=1, ACK=0 from 198.51.100.44:54201`
            : type === 'port_scan'
            ? `> Flow Builder: Rapid probes across 120 destination ports in 500ms window`
            : `> Flow Builder: ICMP Echo payload anomaly detected (burst velocity > 200 pkts/s)`,
        ],
      }));
    }, 800);

    // Step 2: Rule Engine Trigger
    setTimeout(() => {
      soundFx.playThreatAlert();
      const threatName =
        type === 'syn_flood'
          ? 'RULE-001: SYN FLOOD SIGNATURE'
          : type === 'port_scan'
          ? 'RULE-002: HORIZONTAL/VERTICAL PORT SCAN'
          : 'RULE-003: ICMP SMURF FLOOD BURST';

      setSim((prev) => ({
        ...prev,
        step: 3,
        packetsSent: type === 'syn_flood' ? 1650 : type === 'port_scan' ? 350 : 980,
        detectedThreat: threatName,
        riskScore: 92,
        riskLevel: 'critical',
        mitigationStatus: 'THREAT CONFIRMED - SCORING ENGINE ENGAGED',
        logs: [
          ...prev.logs,
          `[ALERT] Deterministic Rule Triggered: ${threatName}`,
          `> Risk Engine: Evaluated evidence vector, assigned severity: CRITICAL (Score: 92/100)`,
        ],
      }));
    }, 1800);

    // Step 3: Policy Execution
    setTimeout(() => {
      soundFx.playSuccessTone();
      setSim((prev) => ({
        ...prev,
        step: 4,
        active: false,
        mitigationStatus: 'POLICY EXECUTED (SIMULATED DROP & IP BLOCK)',
        logs: [
          ...prev.logs,
          `> Policy Engine: Recommended Action = BLOCK_SOURCE_IP (198.51.100.44)`,
          `> Response Engine: Simulated iptables DROP table rule injected.`,
          `[SUCCESS] Security Event persisted into SQLite (ID: sec-evt-${Math.floor(Math.random() * 90000 + 10000)}).`,
        ],
      }));
    }, 2900);
  };

  return (
    <section className="section-wrapper" id="simulator-section">
      <div className="section-header">
        <span className="section-index">02 // INTERACTIVE SANDBOX</span>
        <h2 className="section-heading">REAL-TIME THREAT DETECTION SIMULATOR</h2>
        <p className="section-subtext">
          Trigger live simulated cyber attacks and observe AEGIS dissect the protocol payloads, compute risk metrics, and execute defensive containment policies.
        </p>
      </div>

      <div className="interactive-sandbox swiss-box">
        {/* Controls & Triggers */}
        <div className="sandbox-controls">
          <div>
            <div style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: 8 }}>
              SELECT ATTACK VECTOR TO INJECT
            </div>
            <div className="attack-btn-grid">
              <button
                type="button"
                className={`attack-btn ${sim.type === 'syn_flood' && sim.active ? 'active' : ''}`}
                onClick={() => runSimulation('syn_flood')}
                disabled={sim.active}
              >
                <span className="attack-icon">⚡</span>
                <span style={{ fontWeight: 700 }}>SYN FLOOD</span>
                <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>DoS Probe</span>
              </button>

              <button
                type="button"
                className={`attack-btn ${sim.type === 'port_scan' && sim.active ? 'active' : ''}`}
                onClick={() => runSimulation('port_scan')}
                disabled={sim.active}
              >
                <span className="attack-icon">🔍</span>
                <span style={{ fontWeight: 700 }}>PORT SCAN</span>
                <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>Nmap -sS Recon</span>
              </button>

              <button
                type="button"
                className={`attack-btn ${sim.type === 'icmp_burst' && sim.active ? 'active' : ''}`}
                onClick={() => runSimulation('icmp_burst')}
                disabled={sim.active}
              >
                <span className="attack-icon">💥</span>
                <span style={{ fontWeight: 700 }}>ICMP BURST</span>
                <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>Ping Smurf</span>
              </button>
            </div>
          </div>

          {/* Realtime Detection Gauge */}
          <div style={{ background: 'var(--bg-void)', border: '1px solid var(--border-hairline)', padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 11 }}>
              <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>HEURISTIC RISK SCORE:</span>
              <span style={{
                color: sim.riskLevel === 'critical' ? 'var(--terminal-red)' : sim.riskLevel === 'medium' ? 'var(--terminal-amber)' : 'var(--terminal-green)',
                fontWeight: 700
              }}>
                {sim.riskScore} / 100 [{sim.riskLevel.toUpperCase()}]
              </span>
            </div>

            {/* Visual Risk Gauge Bar */}
            <div style={{ height: 8, background: '#18181b', borderRadius: 2, overflow: 'hidden', marginBottom: 14 }}>
              <div
                style={{
                  height: '100%',
                  width: `${sim.riskScore}%`,
                  background: sim.riskLevel === 'critical' ? 'var(--terminal-red)' : sim.riskLevel === 'medium' ? 'var(--terminal-amber)' : 'var(--terminal-green)',
                  transition: 'all 0.4s ease',
                  boxShadow: sim.riskScore > 70 ? '0 0 12px var(--terminal-red)' : 'none',
                }}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11 }}>
              <div>
                <div style={{ color: 'var(--text-dim)' }}>PACKETS EVALUATED</div>
                <div style={{ color: '#ffffff', fontWeight: 700 }}>{sim.packetsSent} pkts</div>
              </div>
              <div>
                <div style={{ color: 'var(--text-dim)' }}>DEFENSE STATE</div>
                <div style={{ color: 'var(--terminal-cyan)', fontWeight: 700 }}>{sim.mitigationStatus}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Live Event Stream Teletype */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8, fontSize: 11 }}>
            <span style={{ color: 'var(--text-dim)', textTransform: 'uppercase' }}>SIMULATOR REALTIME TELEMETRY</span>
            {sim.active && <span style={{ color: 'var(--terminal-red)' }}>● INJECTION IN PROGRESS</span>}
          </div>

          <pre className="code-block" style={{ height: 220, fontSize: 11, color: 'var(--terminal-green)' }}>
            {sim.logs.map((log, idx) => (
              <div key={idx} style={{ marginBottom: 4 }}>
                {log}
              </div>
            ))}
          </pre>
        </div>
      </div>
    </section>
  );
};

export default AttackSimulatorSection;
