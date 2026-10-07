import { formatNumber } from './format';

/**
 * Detection evidence comes in the engine's structured shape
 *   { observation, features, thresholds, comparisons }
 * (app/detection/rules/*.py) or, for hand-written records, as flat key/value pairs.
 * These helpers read either.
 */

export type EvidenceCheck = {
  feature: string;
  operator: string;
  threshold: string;
  value: unknown;
  thresholdValue: unknown;
  met: boolean;
};

export type EvidenceEntry = { key: string; value: string; numeric: boolean };

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

const COMPARISON = /^\s*([\w.]+)\s*(>=|<=|==|>|<)\s*([\w.]+)\s*$/;

export function readChecks(evidence: Record<string, unknown>): EvidenceCheck[] {
  const comparisons = asRecord(evidence.comparisons);
  if (!comparisons) return [];
  const features = asRecord(evidence.features) ?? {};
  const thresholds = asRecord(evidence.thresholds) ?? {};
  const checks: EvidenceCheck[] = [];
  for (const [expression, met] of Object.entries(comparisons)) {
    const match = COMPARISON.exec(expression);
    if (!match) continue;
    const [, feature, operator, threshold] = match;
    checks.push({
      feature,
      operator,
      threshold,
      value: features[feature],
      thresholdValue: thresholds[threshold],
      met: met === true,
    });
  }
  return checks;
}

export function formatValue(value: unknown): string {
  if (typeof value === 'number') return formatNumber(value);
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value === null || value === undefined) return '—';
  return JSON.stringify(value);
}

/** Every primitive in the evidence except the parts already shown as checks. */
export function readEntries(evidence: Record<string, unknown>): EvidenceEntry[] {
  const structured = asRecord(evidence.features);
  const source = structured ?? evidence;
  const shownInChecks = new Set(readChecks(evidence).map((check) => check.feature));
  return Object.entries(source)
    .filter(([key]) => !shownInChecks.has(key))
    .filter(([key]) => structured !== null || !['observation', 'thresholds', 'comparisons'].includes(key))
    .map(([key, value]) => ({ key, value: formatValue(value), numeric: typeof value === 'number' }));
}

/** The values a reader should see first: the checked features, else the first numbers. */
export function readHeadlineMetrics(evidence: Record<string, unknown>, max = 2): { key: string; value: string }[] {
  const checks = readChecks(evidence);
  if (checks.length > 0) {
    return checks.slice(0, max).map((check) => ({ key: check.feature, value: formatValue(check.value) }));
  }
  return readEntries(evidence)
    .filter((entry) => entry.numeric)
    .slice(0, max)
    .map(({ key, value }) => ({ key, value }));
}
