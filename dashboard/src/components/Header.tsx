export default function Header() {
  return (
    <header className="panel header">
      <div>
        <p className="eyebrow">AEGIS</p>
        <h1>Network Intrusion Detection Dashboard</h1>
        <p className="subtitle">Response outcomes shown from persisted AEGIS events.</p>
      </div>
      <div className="readonly-badge" aria-label="Read-only dashboard">
        READ-ONLY
      </div>
    </header>
  );
}
