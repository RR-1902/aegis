import { useId, useMemo, useState, type CSSProperties } from 'react';
import { THRESHOLDS, runLab, type LabInput } from '../lib/engine';
import { formatNumber, humanize } from '../lib/format';
import RiskMeter from './RiskMeter';
import { LevelTag, OutcomeTag } from './Tags';
import SectionHead from './landing/SectionHead';

const PRESETS: { label: string; values: Pick<LabInput, 'synRate' | 'incompleteRatio' | 'uniquePorts'> }[] = [
  { label: 'Quiet window', values: { synRate: 1.2, incompleteRatio: 0.1, uniquePorts: 2 } },
  { label: 'SYN flood', values: { synRate: 36, incompleteRatio: 0.92, uniquePorts: 1 } },
  { label: 'Port scan', values: { synRate: 4.6, incompleteRatio: 0.35, uniquePorts: 48 } },
  { label: 'Both', values: { synRate: 36, incompleteRatio: 0.92, uniquePorts: 48 } },
];

type SliderProps = {
  label: string;
  feature: string;
  value: number;
  min: number;
  max: number;
  step: number;
  threshold: number;
  unit?: string;
  onChange: (value: number) => void;
};

function FeatureSlider({ label, feature, value, min, max, step, threshold, unit, onChange }: SliderProps) {
  const id = useId();
  const position = ((threshold - min) / (max - min)) * 100;
  return (
    <div className="lab-field">
      <div className="lab-field__head">
        <label htmlFor={id}>{label}</label>
        <input
          className="lab-field__number"
          type="number"
          inputMode="decimal"
          aria-label={`${label}, exact value`}
          min={min}
          max={max}
          step={step}
          value={value}
          onChange={(event) => {
            const next = Number(event.target.value);
            if (!Number.isNaN(next)) onChange(Math.max(min, Math.min(max, next)));
          }}
        />
      </div>
      <div className="lab-field__track" style={{ '--threshold': `${position}%` } as CSSProperties}>
        <input
          id={id}
          type="range"
          min={min}
          max={max}
          step={step}
          value={value}
          onChange={(event) => onChange(Number(event.target.value))}
        />
        <span className="lab-field__tick" aria-hidden="true" />
      </div>
      <p className="lab-field__meta">
        <code>{feature}</code>
        <span>
          Threshold {formatNumber(threshold)}
          {unit}
        </span>
      </p>
    </div>
  );
}

function Toggle({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="toggle">
      <input id={id} type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <label htmlFor={id}>
        <span className="toggle__label">{label}</span>
        <span className="toggle__hint">{hint}</span>
      </label>
    </div>
  );
}

export default function RuleLab() {
  const [input, setInput] = useState<LabInput>({
    synRate: 36,
    incompleteRatio: 0.92,
    uniquePorts: 1,
    sourceAttributed: false,
    safeMode: true,
  });
  const result = useMemo(() => runLab(input), [input]);
  const set = <K extends keyof LabInput>(key: K) => (value: LabInput[K]) =>
    setInput((current) => ({ ...current, [key]: value }));

  return (
    <section className="section lab-section" id="rule-lab" aria-labelledby="lab-title">
      <SectionHead id="lab-title" label="Rule lab" icon="threshold" title="Try the rules yourself">
        <p>
          Set the feature values for one five-second window and watch the verdict form, using the same
          thresholds, points and policy as the backend. Nothing here is sent to the API or written to the
          ledger.
        </p>
      </SectionHead>

      <div className="lab" data-reveal="">
        <form className="lab__inputs" onSubmit={(event) => event.preventDefault()} aria-label="Window features">
          <div className="presets" role="group" aria-label="Example windows">
            {PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                className="button button--small"
                onClick={() => setInput((current) => ({ ...current, ...preset.values }))}
              >
                {preset.label}
              </button>
            ))}
          </div>

          <FeatureSlider
            label="SYN packets per second"
            feature="syn_rate"
            value={input.synRate}
            min={0}
            max={60}
            step={0.1}
            threshold={THRESHOLDS.synRate}
            unit=" per second"
            onChange={set('synRate')}
          />
          <FeatureSlider
            label="Connections left incomplete"
            feature="incomplete_connection_ratio"
            value={input.incompleteRatio}
            min={0}
            max={1}
            step={0.01}
            threshold={THRESHOLDS.synIncompleteRatio}
            onChange={set('incompleteRatio')}
          />
          <FeatureSlider
            label="Unique destination ports"
            feature="unique_destination_ports"
            value={input.uniquePorts}
            min={0}
            max={60}
            step={1}
            threshold={THRESHOLDS.portScanPorts}
            onChange={set('uniquePorts')}
          />

          <Toggle
            label="Evidence names the source"
            hint="Blocking needs an observed source address in the evidence. The shipped rules do not attach one yet, so the live pipeline never recommends a block."
            checked={input.sourceAttributed}
            onChange={set('sourceAttributed')}
          />
          <Toggle
            label="SAFE_MODE"
            hint="On by default. Turned off, a block would have to run for real, and the response engine rejects it because no executor is installed."
            checked={input.safeMode}
            onChange={set('safeMode')}
          />
        </form>

        <div className="lab__verdict" aria-live="polite">
          {!result.recorded ? (
            <div className="verdict-empty">
              <p className="verdict-empty__title">No rule fired</p>
              <p className="muted">
                The pipeline discards windows without detections, so nothing would be recorded for this one.
              </p>
            </div>
          ) : (
            <ol className="verdict">
              <li className="verdict__step">
                <h3 className="verdict__name">
                  <span className="verdict__index">1</span>Detections
                </h3>
                <ul className="verdict__rules">
                  {result.detections.map((detection) => (
                    <li key={detection.ruleId}>
                      <p className="verdict__rule">
                        <span>{detection.ruleName}</span>
                        <LevelTag level={detection.severity} />
                        <span className="points">+{detection.points}</span>
                      </p>
                      {detection.checks.map((check) => (
                        <p className="check" key={check.feature} data-met={check.met}>
                          <code>{check.feature}</code>
                          <span>
                            {formatNumber(check.value)} ≥ {formatNumber(check.threshold)}
                          </span>
                        </p>
                      ))}
                    </li>
                  ))}
                </ul>
              </li>

              <li className="verdict__step">
                <h3 className="verdict__name">
                  <span className="verdict__index">2</span>Risk
                </h3>
                <p className="verdict__score" data-level={result.level}>
                  {result.score}
                  <span className="trace__of">/100</span>
                </p>
                <RiskMeter score={result.score} level={result.level} />
                <p className="muted">
                  {result.detections.map((detection) => `${detection.ruleName} ${detection.points}`).join(' + ')}
                  {result.detections.length > 1 ? ` = ${result.score}` : ''}, {humanize(result.level).toLowerCase()} risk
                </p>
              </li>

              <li className="verdict__step">
                <h3 className="verdict__name">
                  <span className="verdict__index">3</span>Policy
                </h3>
                <p className="verdict__value">
                  {humanize(result.policy.action)}
                  {result.policy.executionMode !== 'none' && (
                    <span className="verdict__mode">{humanize(result.policy.executionMode)}</span>
                  )}
                </p>
                <p className="muted">{result.policy.reason}</p>
              </li>

              <li className="verdict__step">
                <h3 className="verdict__name">
                  <span className="verdict__index">4</span>Response
                </h3>
                <p className="verdict__value">
                  <OutcomeTag status={result.response.status} />
                </p>
                <p className="muted">{result.response.message}</p>
                <p className="verdict__level">
                  Stored as a {result.level}-risk event with the outcome{' '}
                  <strong>{humanize(result.response.status).toLowerCase()}</strong>.
                </p>
              </li>
            </ol>
          )}
        </div>
      </div>
    </section>
  );
}
