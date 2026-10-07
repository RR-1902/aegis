/**
 * Browser copy of the AEGIS decision chain, used by the rule lab.
 *
 * Every constant and branch mirrors the Python engine so the lab gives the same verdict the
 * backend would for the same feature values:
 *   thresholds and points  app/config/settings.py
 *   rules                  app/detection/rules/syn_flood.py, port_scan.py
 *   scoring                app/scoring/risk_scorer.py
 *   policy                 app/policy/engine.py
 *   response               app/response/engine.py
 * Keep them in sync when the backend defaults change.
 */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type Severity = 'medium' | 'high';
export type RuleId = 'syn_flood' | 'port_scan';
export type PolicyAction = 'log_only' | 'alert_only' | 'block_source';
export type ExecutionMode = 'none' | 'simulate' | 'execute';
export type ResponseStatus = 'no_action' | 'simulated' | 'rejected';

export const THRESHOLDS = {
  /** SYN_RATE_THRESHOLD: SYN packets per second. */
  synRate: 10.0,
  /** SYN_INCOMPLETE_RATIO: share of connection attempts that never complete. */
  synIncompleteRatio: 0.7,
  /** PORT_SCAN_THRESHOLD: unique destination ports in one observation. */
  portScanPorts: 20,
} as const;

export const POINTS: Record<RuleId, Record<Severity, number>> = {
  port_scan: { medium: 25, high: 40 },
  syn_flood: { medium: 35, high: 55 },
};

/** Inclusive upper bound of each level (THREAT_SCORE_LOW / MEDIUM / HIGH). */
export const LEVEL_BOUNDS = { low: 29, medium: 59, high: 79 } as const;

export const LEVELS: RiskLevel[] = ['low', 'medium', 'high', 'critical'];

export const RULE_NAMES: Record<RuleId, string> = {
  syn_flood: 'SYN Flood',
  port_scan: 'Port Scan',
};

export type Check = {
  feature: string;
  value: number;
  threshold: number;
  met: boolean;
};

export type LabDetection = {
  ruleId: RuleId;
  ruleName: string;
  severity: Severity;
  points: number;
  checks: Check[];
};

export type PolicyDecision = {
  action: PolicyAction;
  executionMode: ExecutionMode;
  reason: string;
};

export type ResponseOutcome = {
  status: ResponseStatus;
  message: string;
};

export type LabInput = {
  synRate: number;
  incompleteRatio: number;
  uniquePorts: number;
  /** Whether a detection's evidence names an observed source. No shipped rule does this yet. */
  sourceAttributed: boolean;
  safeMode: boolean;
};

export type LabResult =
  | { recorded: false; detections: [] }
  | {
      recorded: true;
      detections: LabDetection[];
      score: number;
      level: RiskLevel;
      policy: PolicyDecision;
      response: ResponseOutcome;
    };

export function evaluateSynFlood(synRate: number, incompleteRatio: number): LabDetection | null {
  const rateMet = synRate >= THRESHOLDS.synRate;
  const ratioMet = incompleteRatio >= THRESHOLDS.synIncompleteRatio;
  if (!rateMet || !ratioMet) {
    return null;
  }
  const severity: Severity =
    synRate > THRESHOLDS.synRate && incompleteRatio > THRESHOLDS.synIncompleteRatio ? 'high' : 'medium';
  return {
    ruleId: 'syn_flood',
    ruleName: RULE_NAMES.syn_flood,
    severity,
    points: POINTS.syn_flood[severity],
    checks: [
      { feature: 'syn_rate', value: synRate, threshold: THRESHOLDS.synRate, met: rateMet },
      {
        feature: 'incomplete_connection_ratio',
        value: incompleteRatio,
        threshold: THRESHOLDS.synIncompleteRatio,
        met: ratioMet,
      },
    ],
  };
}

export function evaluatePortScan(uniquePorts: number): LabDetection | null {
  if (uniquePorts < THRESHOLDS.portScanPorts) {
    return null;
  }
  const severity: Severity = uniquePorts > THRESHOLDS.portScanPorts ? 'high' : 'medium';
  return {
    ruleId: 'port_scan',
    ruleName: RULE_NAMES.port_scan,
    severity,
    points: POINTS.port_scan[severity],
    checks: [
      {
        feature: 'unique_destination_ports',
        value: uniquePorts,
        threshold: THRESHOLDS.portScanPorts,
        met: true,
      },
    ],
  };
}

export function mapLevel(score: number): RiskLevel {
  if (score <= LEVEL_BOUNDS.low) return 'low';
  if (score <= LEVEL_BOUNDS.medium) return 'medium';
  if (score <= LEVEL_BOUNDS.high) return 'high';
  return 'critical';
}

export function scoreDetections(detections: LabDetection[]): { score: number; level: RiskLevel } {
  const total = detections.reduce((sum, detection) => sum + detection.points, 0);
  const score = Math.min(total, 100);
  return { score, level: mapLevel(score) };
}

export function decidePolicy(
  level: RiskLevel,
  detections: LabDetection[],
  sourceAttributed: boolean,
  safeMode: boolean,
): PolicyDecision {
  if (level === 'low') {
    return { action: 'log_only', executionMode: 'none', reason: 'Low risk is logged without an alert.' };
  }
  if (level === 'medium') {
    return { action: 'alert_only', executionMode: 'none', reason: 'Medium risk raises an alert only.' };
  }

  const ids = new Set(detections.map((detection) => detection.ruleId));
  const blockable = ids.has('syn_flood') || (ids.has('port_scan') && level === 'critical');
  if (blockable && sourceAttributed) {
    return {
      action: 'block_source',
      executionMode: safeMode ? 'simulate' : 'execute',
      reason: ids.has('syn_flood')
        ? 'SYN flood evidence names an observed source, so blocking it is recommended.'
        : 'Critical port-scan risk with an observed source, so blocking it is recommended.',
    };
  }
  return {
    action: 'alert_only',
    executionMode: 'none',
    reason: blockable
      ? 'Blocking needs the evidence to name an observed source. It does not, so AEGIS alerts instead.'
      : 'High port-scan risk alone does not justify blocking, so AEGIS alerts instead.',
  };
}

export function respond(policy: PolicyDecision, safeMode: boolean): ResponseOutcome {
  if (policy.action !== 'block_source') {
    return { status: 'no_action', message: 'No external action taken.' };
  }
  if (safeMode) {
    return { status: 'simulated', message: 'Block simulated. No system state changed.' };
  }
  return {
    status: 'rejected',
    message: 'Rejected: real execution is unavailable because no action executor is installed.',
  };
}

export function runLab(input: LabInput): LabResult {
  // Rules run in the engine's configured order: port scan, then SYN flood.
  const detections = [evaluatePortScan(input.uniquePorts), evaluateSynFlood(input.synRate, input.incompleteRatio)].filter(
    (detection): detection is LabDetection => detection !== null,
  );

  // The pipeline drops observations without detections; nothing is persisted.
  if (detections.length === 0) {
    return { recorded: false, detections: [] };
  }

  const { score, level } = scoreDetections(detections);
  const policy = decidePolicy(level, detections, input.sourceAttributed, input.safeMode);
  return {
    recorded: true,
    detections,
    score,
    level,
    policy,
    response: respond(policy, input.safeMode),
  };
}
