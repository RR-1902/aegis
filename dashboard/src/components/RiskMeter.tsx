import { LEVEL_BOUNDS } from '../lib/engine';

type RiskMeterProps = {
  score: number;
  level: string;
  /** Show the band boundaries (30, 60, 80) under the bar. */
  scale?: boolean;
};

const BANDS = [
  { level: 'low', from: 0, to: LEVEL_BOUNDS.low + 1 },
  { level: 'medium', from: LEVEL_BOUNDS.low + 1, to: LEVEL_BOUNDS.medium + 1 },
  { level: 'high', from: LEVEL_BOUNDS.medium + 1, to: LEVEL_BOUNDS.high + 1 },
  { level: 'critical', from: LEVEL_BOUNDS.high + 1, to: 100 },
];

/** A 0–100 ruler: tinted level bands, with the score filled in its level colour. */
export default function RiskMeter({ score, level, scale = false }: RiskMeterProps) {
  const clamped = Math.max(0, Math.min(100, score));
  return (
    <div className="meter" data-level={level.toLowerCase()}>
      <div
        className="meter__track"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        aria-label={`Risk score ${clamped} of 100`}
      >
        {BANDS.map((band) => (
          <span
            key={band.level}
            className="meter__band"
            data-level={band.level}
            style={{ left: `${band.from}%`, width: `${band.to - band.from}%` }}
          />
        ))}
        <span className="meter__fill" style={{ transform: `scaleX(${clamped / 100})` }} />
      </div>
      {scale && (
        <div className="meter__scale" aria-hidden="true">
          <span style={{ left: '0%' }}>0</span>
          <span style={{ left: `${LEVEL_BOUNDS.low + 1}%` }}>{LEVEL_BOUNDS.low + 1}</span>
          <span style={{ left: `${LEVEL_BOUNDS.medium + 1}%` }}>{LEVEL_BOUNDS.medium + 1}</span>
          <span style={{ left: `${LEVEL_BOUNDS.high + 1}%` }}>{LEVEL_BOUNDS.high + 1}</span>
          <span style={{ left: '100%' }}>100</span>
        </div>
      )}
    </div>
  );
}
