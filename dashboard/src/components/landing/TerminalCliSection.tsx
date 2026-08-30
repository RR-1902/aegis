import React, { useState } from 'react';
import { soundFx } from '../../utils/soundFx';

type HistoryEntry = {
  command: string;
  output: React.ReactNode;
};

export const TerminalCliSection: React.FC = () => {
  const [inputVal, setInputVal] = useState('');
  const [history, setHistory] = useState<HistoryEntry[]>([
    {
      command: 'aegis --version',
      output: 'AEGIS Intelligent Intrusion Detection Engine v2.4.0 (Python 3.11 / AF_PACKET / Scapy)',
    },
    {
      command: 'aegis status',
      output: (
        <div>
          <div>[+] ENGINE STATUS: ARMED &amp; OBSERVING</div>
          <div>[+] INTERFACE: eth0 (Promiscuous Mode = True, MTU = 1500)</div>
          <div>[+] BPF FILTER: "ip and (tcp or udp or icmp)"</div>
          <div>[+] ACTIVE FLOW BUCKETS: 4,192 / 65,536 (Memory: 1.84 MB)</div>
          <div>[+] PERSISTENCE LEDGER: SQLite (WAL Mode, Events: 1,420)</div>
          <div>Type <span style={{ color: 'var(--terminal-green)' }}>'help'</span> for a list of available subcommands.</div>
        </div>
      ),
    },
  ]);

  const executeCommand = (rawCmd: string) => {
    const cmd = rawCmd.trim().toLowerCase();
    soundFx.playKeyClick();

    let output: React.ReactNode = null;

    switch (cmd) {
      case 'help':
        output = (
          <div>
            <div style={{ color: 'var(--terminal-green)', marginBottom: 4 }}>AVAILABLE AEGIS CLI COMMANDS:</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>status</span> : Display kernel capture status &amp; flow metrics</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>rules</span> : List loaded deterministic detection rules</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>flows</span> : Inspect active 5-tuple sliding-window tables</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>api</span> : Probe backend REST API endpoints</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>simulate syn-flood</span> : Trigger simulated SYN flood test</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>export json</span> : Dump security telemetry configuration</div>
            <div>• <span style={{ color: 'var(--terminal-cyan)' }}>clear</span> : Reset terminal output</div>
          </div>
        );
        break;

      case 'status':
        output = (
          <div>
            <div>[●] DAEMON: Running (PID: 4892)</div>
            <div>[●] INGRESS: 18,400 pkts/sec (Peak: 42,000 pkts/sec)</div>
            <div>[●] CPU OVERHEAD: 1.2% · MEMORY: 34 MB</div>
            <div>[●] THREAT LEVEL: NOMINAL (Risk Index: 0.04)</div>
          </div>
        );
        break;

      case 'rules':
        output = (
          <div>
            <div>1. [RULE-SYN-01] SYN Flood Threshold: syn_rate &gt; 50/s &amp; syn_ratio &gt; 0.85 (Severity: HIGH)</div>
            <div>2. [RULE-SCAN-02] Port Scan Probe: unique_dports &gt; 15 in 2.0s window (Severity: HIGH)</div>
            <div>3. [RULE-ICMP-03] ICMP Smurf Flood: icmp_rate &gt; 100/s (Severity: MEDIUM)</div>
            <div>4. [RULE-ANOM-04] Abnormal Connection Abort: rst_count &gt; 40 in 5s (Severity: MEDIUM)</div>
          </div>
        );
        break;

      case 'flows':
        output = (
          <div>
            <div>TCP  192.168.1.45:51022  &lt;--&gt;  10.0.0.5:443    [Pkts: 1,240  Bytes: 1.2MB  SYN_ACK: OK]</div>
            <div>TCP  192.168.1.88:49201  &lt;--&gt;  10.0.0.2:80     [Pkts: 48     Bytes: 12KB   SYN_ACK: OK]</div>
            <div>UDP  192.168.1.12:5353   &lt;--&gt;  224.0.0.251:5353 [Pkts: 6      Bytes: 1.4KB  MCAST: OK]</div>
          </div>
        );
        break;

      case 'api':
        output = (
          <div>
            <div>GET /api/v1/health   ➔ HTTP 200 OK  [status: "ok", database: "ok", app_name: "AEGIS"]</div>
            <div>GET /api/v1/events   ➔ HTTP 200 OK  [items: 50, count: 1420, limit: 50]</div>
            <div>GET /api/v1/events/{'{id}'} ➔ HTTP 200 OK  [causal_chain: "Detection ➔ Risk ➔ Policy ➔ Response"]</div>
          </div>
        );
        break;

      case 'simulate syn-flood':
        soundFx.playThreatAlert();
        output = (
          <div style={{ color: 'var(--terminal-red)' }}>
            <div>[SIM_ATTACK] Injected 500 SYN packets with spoofed source IPs.</div>
            <div>[ALERT] RULE-SYN-01 triggered. Risk Score calculated: 94 / 100 [CRITICAL].</div>
            <div>[ACTION] Simulated IP drop rule generated. Event persisted into SQLite.</div>
          </div>
        );
        break;

      case 'export json':
        output = (
          <pre style={{ color: 'var(--terminal-green)', fontSize: 11 }}>
{`{
  "system": "AEGIS-NIDS",
  "version": "2.4.0",
  "policy": {
    "execution_mode": "simulate",
    "risk_threshold": 70,
    "default_action": "block_source"
  },
  "database": "aegis.db",
  "bpf_filter": "ip and (tcp or udp or icmp)"
}`}
          </pre>
        );
        break;

      case 'clear':
        setHistory([]);
        return;

      default:
        output = (
          <div style={{ color: 'var(--terminal-red)' }}>
            Command not recognized: "{rawCmd}". Type <span style={{ color: 'var(--terminal-green)' }}>'help'</span> for available commands.
          </div>
        );
        break;
    }

    setHistory((prev) => [...prev, { command: rawCmd, output }]);
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputVal.trim()) return;
    executeCommand(inputVal);
    setInputVal('');
  };

  return (
    <section className="section-wrapper" id="cli-section">
      <div className="section-header">
        <span className="section-index">04 // INTERACTIVE SHELL</span>
        <h2 className="section-heading">EMBEDDED AEGIS TERMINAL CONSOLE</h2>
        <p className="section-subtext">
          Direct terminal interface into the AEGIS runtime. Inspect live rule thresholds, flow tables, and system diagnostics.
        </p>
      </div>

      <div className="interactive-cli swiss-box">
        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-hairline)', paddingBottom: 8, marginBottom: 12 }}>
          <span style={{ color: 'var(--terminal-green)', fontSize: 11 }}>
            AEGIS_CLI_SESSION // TTY_01 [AUTHENTICATED]
          </span>
          <div style={{ display: 'flex', gap: 10 }}>
            {['status', 'rules', 'flows', 'help'].map((cmd) => (
              <button
                key={cmd}
                type="button"
                className="btn-toggle"
                style={{ fontSize: 10, padding: '2px 6px' }}
                onClick={() => executeCommand(cmd)}
              >
                ${cmd}
              </button>
            ))}
          </div>
        </div>

        <div className="cli-history">
          {history.map((item, idx) => (
            <div key={idx} className="cli-line">
              <div style={{ display: 'flex', alignItems: 'center' }}>
                <span className="cli-prompt">aegis@core:~$</span>
                <span style={{ color: '#ffffff' }}>{item.command}</span>
              </div>
              <div style={{ paddingLeft: 16, marginTop: 4, color: '#a1a1aa' }}>
                {item.output}
              </div>
            </div>
          ))}
        </div>

        <form className="cli-input-form" onSubmit={handleFormSubmit}>
          <span className="cli-prompt">aegis@core:~$</span>
          <input
            type="text"
            className="cli-input"
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            placeholder="Type 'help', 'status', 'rules', 'flows', or 'simulate syn-flood'..."
            autoComplete="off"
            spellCheck="false"
          />
          <span className="terminal-cursor" />
        </form>
      </div>
    </section>
  );
};

export default TerminalCliSection;
