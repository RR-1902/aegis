export default function Header() {
  return (
    <header className="panel header swiss-box">
      <div>
        <p className="eyebrow">// AEGIS_SECURITY_OPERATIONS_GRID</p>
        <h1>Network Intrusion Detection Dashboard</h1>
        <p className="subtitle">Response outcomes shown from persisted AEGIS events.</p>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--terminal-green)' }}>
          ● BPF_AF_PACKET
        </span>
        <div className="readonly-badge" aria-label="Read-only dashboard">
          READ-ONLY
        </div>
      </div>
    </header>
  );
}

