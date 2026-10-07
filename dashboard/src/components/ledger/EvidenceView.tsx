import { formatValue, readChecks, readEntries } from '../../lib/evidence';

const OPERATOR_TEXT: Record<string, string> = { '>=': '≥', '<=': '≤', '>': '>', '<': '<', '==': '=' };

export default function EvidenceView({ evidence }: { evidence: Record<string, unknown> }) {
  const checks = readChecks(evidence);
  const entries = readEntries(evidence);

  if (checks.length === 0 && entries.length === 0) {
    return <p className="muted">This detection recorded no evidence values.</p>;
  }

  return (
    <div className="evidence">
      {checks.length > 0 && (
        <table className="evidence__table">
          <caption>Threshold checks</caption>
          <tbody>
            {checks.map((check) => (
              <tr key={`${check.feature}-${check.threshold}`} data-met={check.met}>
                <th scope="row">
                  <code>{check.feature}</code>
                </th>
                <td className="num">
                  {formatValue(check.value)} {OPERATOR_TEXT[check.operator] ?? check.operator}{' '}
                  {formatValue(check.thresholdValue)}
                </td>
                <td className="evidence__met">{check.met ? 'Met' : 'Not met'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {entries.length > 0 && (
        <table className="evidence__table">
          <caption>{checks.length > 0 ? 'Other features in the window' : 'Evidence'}</caption>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.key}>
                <th scope="row">
                  <code>{entry.key}</code>
                </th>
                <td className={entry.numeric ? 'num' : undefined} colSpan={2}>
                  {entry.value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
