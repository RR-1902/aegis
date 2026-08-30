import type { HealthResponse } from '../types/api';
import { formatDateTime } from '../utils/format';

type Props = {
  health: HealthResponse | null;
  healthError: string | null;
  lastRefresh: string | null;
  loading: boolean;
};

export default function StatusBar({ health, healthError, lastRefresh, loading }: Props) {
  return (
    <section className="panel status-bar swiss-box" aria-label="System status">
      <div className="status-item">
        <span className={`status-dot ${health && !healthError ? 'ok' : 'error'}`} />
        <div>
          <div className="status-label">API TELEMETRY</div>
          <div className="status-value">
            {loading ? 'Loading health...' : healthError ? 'Backend unavailable' : health?.status ?? 'Unknown'}
          </div>
        </div>
      </div>

      <div className="status-item">
        <span className={`status-dot ${health?.database === 'ok' && !healthError ? 'ok' : 'error'}`} />
        <div>
          <div className="status-label">SQLITE LEDGER</div>
          <div className="status-value">{loading ? 'Loading health...' : healthError ? 'Unavailable' : health?.database ?? 'Unknown'}</div>
        </div>
      </div>

      <div className="status-item">
        <div>
          <div className="status-label">LAST SYNC</div>
          <div className="status-value">{formatDateTime(lastRefresh)}</div>
        </div>
      </div>
    </section>
  );
}

