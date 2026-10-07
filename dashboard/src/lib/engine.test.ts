import { describe, expect, it } from 'vitest';
import { decidePolicy, evaluatePortScan, evaluateSynFlood, mapLevel, runLab } from './engine';

// Expected values mirror tests/test_detection_rules.py, test_scoring.py and test_policy_engine.py.

describe('rules', () => {
  it('fires SYN flood only when both thresholds are met', () => {
    expect(evaluateSynFlood(9.99, 1)).toBeNull();
    expect(evaluateSynFlood(30, 0.69)).toBeNull();
    expect(evaluateSynFlood(10, 0.7)?.severity).toBe('medium');
    expect(evaluateSynFlood(10, 0.9)?.severity).toBe('medium');
    expect(evaluateSynFlood(10.5, 0.71)?.severity).toBe('high');
  });

  it('fires port scan at 20 unique ports and is high above it', () => {
    expect(evaluatePortScan(19)).toBeNull();
    expect(evaluatePortScan(20)?.severity).toBe('medium');
    expect(evaluatePortScan(21)?.severity).toBe('high');
  });
});

describe('scoring', () => {
  it('maps level boundaries', () => {
    expect([29, 30, 59, 60, 79, 80].map(mapLevel)).toEqual(['low', 'medium', 'medium', 'high', 'high', 'critical']);
  });

  it.each([
    [{ synRate: 0, incompleteRatio: 0, uniquePorts: 20 }, 25, 'low'],
    [{ synRate: 0, incompleteRatio: 0, uniquePorts: 21 }, 40, 'medium'],
    [{ synRate: 10, incompleteRatio: 0.7, uniquePorts: 0 }, 35, 'medium'],
    [{ synRate: 30, incompleteRatio: 1, uniquePorts: 0 }, 55, 'medium'],
    [{ synRate: 10, incompleteRatio: 0.7, uniquePorts: 20 }, 60, 'high'],
    [{ synRate: 30, incompleteRatio: 1, uniquePorts: 20 }, 80, 'critical'],
    [{ synRate: 30, incompleteRatio: 1, uniquePorts: 24 }, 95, 'critical'],
  ])('scores %o as %i (%s)', (features, score, level) => {
    const result = runLab({ ...features, sourceAttributed: false, safeMode: true });
    expect(result.recorded).toBe(true);
    if (result.recorded) {
      expect(result.score).toBe(score);
      expect(result.level).toBe(level);
    }
  });

  it('records nothing when no rule fires', () => {
    expect(runLab({ synRate: 1, incompleteRatio: 0.1, uniquePorts: 2, sourceAttributed: false, safeMode: true }).recorded).toBe(false);
  });
});

describe('policy and response', () => {
  const critical = { synRate: 30, incompleteRatio: 1, uniquePorts: 24 };

  it('alerts instead of blocking without an observed source', () => {
    const result = runLab({ ...critical, sourceAttributed: false, safeMode: true });
    expect(result.recorded && result.policy.action).toBe('alert_only');
    expect(result.recorded && result.response.status).toBe('no_action');
  });

  it('simulates a block with an observed source and SAFE_MODE on', () => {
    const result = runLab({ ...critical, sourceAttributed: true, safeMode: true });
    expect(result.recorded && result.policy).toMatchObject({ action: 'block_source', executionMode: 'simulate' });
    expect(result.recorded && result.response.status).toBe('simulated');
  });

  it('rejects a real block because no executor exists', () => {
    const result = runLab({ ...critical, sourceAttributed: true, safeMode: false });
    expect(result.recorded && result.policy.executionMode).toBe('execute');
    expect(result.recorded && result.response.status).toBe('rejected');
  });

  it('never blocks a high port scan that is not critical', () => {
    const portScan = evaluatePortScan(24);
    expect(portScan).not.toBeNull();
    expect(decidePolicy('high', portScan ? [portScan] : [], true, true).action).toBe('alert_only');
  });
});
