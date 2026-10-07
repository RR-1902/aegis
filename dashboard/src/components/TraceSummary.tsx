import type { CSSProperties, ReactNode } from 'react';
import type { SecurityEvent } from '../types/api';
import { readHeadlineMetrics } from '../lib/evidence';
import { formatDay, formatWindow, humanize, windowSeconds } from '../lib/format';
import RiskMeter from './RiskMeter';
import { LevelTag, OutcomeTag } from './Tags';

type Stage = {
  key: string;
  name: string;
  body: ReactNode;
};

/**
 * One event's decision chain in five stages: window, detection, risk, policy, response.
 * Remounting it (by key) replays the draw-in.
 */
export default function TraceSummary({ event }: { event: SecurityEvent }) {
  const seconds = windowSeconds(event.window_start, event.window_end);
  const detections = event.detections;
  const metrics = detections[0] ? readHeadlineMetrics(detections[0].evidence) : [];
  const level = event.risk.level.toLowerCase();

  const stages: Stage[] = [
    {
      key: 'window',
      name: 'Flow window',
      body: (
        <>
          <p className="trace__value">{seconds === null ? '—' : `${seconds} s`}</p>
          <p className="trace__data">{formatWindow(event.window_start, event.window_end)}</p>
          <p className="trace__note">{formatDay(event.window_start)}</p>
        </>
      ),
    },
    {
      key: 'detection',
      name: detections.length > 1 ? `${detections.length} detections` : 'Detection',
      body: (
        <>
          <p className="trace__value">{detections.map((detection) => detection.rule_name).join(' + ') || 'None'}</p>
          {detections[0] && <LevelTag level={detections[0].severity} />}
          {metrics.map((metric) => (
            <p className="trace__data" key={metric.key}>
              <span className="trace__key">{metric.key}</span> {metric.value}
            </p>
          ))}
        </>
      ),
    },
    {
      key: 'risk',
      name: 'Risk',
      body: (
        <>
          <p className="trace__score" data-level={level}>
            {event.risk.score}
            <span className="trace__of">/100</span>
          </p>
          <RiskMeter score={event.risk.score} level={level} />
          <p className="trace__note">{humanize(level)}</p>
        </>
      ),
    },
    {
      key: 'policy',
      name: 'Policy',
      body: (
        <>
          <p className="trace__value">{humanize(event.policy.recommended_action)}</p>
          <p className="trace__note">Execution: {humanize(event.policy.execution_mode)}</p>
          {event.policy.target && <p className="trace__data">{event.policy.target.ip}</p>}
        </>
      ),
    },
    {
      key: 'response',
      name: 'Response',
      body: (
        <>
          <OutcomeTag status={event.response.status} />
          <p className="trace__note trace__clamp">{event.response.message}</p>
        </>
      ),
    },
  ];

  return (
    <ol className="trace" aria-label="Decision chain" data-level={level}>
      {stages.map((stage, index) => (
        <li
          className="trace__stage"
          key={stage.key}
          // From the risk stage on, the path carries the risk level that drives the decision.
          data-driven={index >= 2 ? '' : undefined}
          style={{ '--i': index } as CSSProperties}
        >
          <div className="trace__rail" aria-hidden="true">
            <span className="trace__node" />
            {index < stages.length - 1 && <span className="trace__line" />}
          </div>
          <p className="trace__name">
            <span className="trace__index">{index + 1}</span>
            {stage.name}
          </p>
          <div className="trace__body">{stage.body}</div>
        </li>
      ))}
    </ol>
  );
}
