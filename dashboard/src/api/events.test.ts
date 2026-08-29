import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fetchEvent, fetchEvents, fetchHealth, validateSecurityEvent } from './events';
import { ApiError } from './client';

const healthPayload = {
  status: 'ok',
  app_name: 'AEGIS',
  app_version: '0.1.0',
  database: 'ok',
};

const eventPayload = {
  event_id: 'security-event:test-1',
  flow_key: {
    src_ip: '10.0.0.1',
    dst_ip: '10.0.0.2',
    protocol: 'TCP',
    src_port: null,
    dst_port: null,
  },
  window_start: '2026-01-01T00:00:00Z',
  window_end: '2026-01-01T00:00:05Z',
  recorded_at: '2026-01-01T00:00:06Z',
  detections: [
    {
      rule_id: 'syn_flood',
      rule_name: 'SYN Flood',
      severity: 'high',
      flow_key: {
        src_ip: '10.0.0.1',
        dst_ip: '10.0.0.2',
        protocol: 'TCP',
        src_port: null,
        dst_port: null,
      },
      window_start: '2026-01-01T00:00:00Z',
      window_end: '2026-01-01T00:00:05Z',
      evidence: { syn_rate: 11.5 },
      explanation: 'High SYN rate observed.',
    },
  ],
  risk: {
    score: 95,
    level: 'critical',
    flow_key: {
      src_ip: '10.0.0.1',
      dst_ip: '10.0.0.2',
      protocol: 'TCP',
      src_port: null,
      dst_port: null,
    },
    window_start: '2026-01-01T00:00:00Z',
    window_end: '2026-01-01T00:00:05Z',
    detections: [],
    explanation: 'Combined score exceeded critical threshold.',
  },
  policy: {
    recommended_action: 'block_source',
    allowed: false,
    execution_mode: 'simulate',
    flow_key: {
      src_ip: '10.0.0.1',
      dst_ip: '10.0.0.2',
      protocol: 'TCP',
      src_port: null,
      dst_port: null,
    },
    window_start: '2026-01-01T00:00:00Z',
    window_end: '2026-01-01T00:00:05Z',
    risk_score: 95,
    risk_level: 'critical',
    detection_ids: ['syn_flood'],
    target: null,
    explanation: 'Simulation only.',
  },
  response: {
    action: 'block_source',
    status: 'simulated',
    simulated: true,
    target: null,
    message: 'No system state changed.',
    error: null,
    timestamp: '2026-01-01T00:00:06Z',
  },
  lifecycle_status: 'simulated',
};

describe('events api client', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('fetches health successfully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => healthPayload,
    }));

    await expect(fetchHealth()).resolves.toEqual(healthPayload);
  });

  it('fetches events successfully', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ items: [eventPayload], count: 1, limit: 50 }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchEvents({ risk_level: 'critical', lifecycle_status: 'simulated', limit: 50 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.count).toBe(1);
    expect(result.items[0].event_id).toBe(eventPayload.event_id);
  });

  it('fetches event details successfully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => eventPayload,
    }));

    await expect(fetchEvent(eventPayload.event_id)).resolves.toEqual(eventPayload);
  });

  it('surfaces network failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));

    await expect(fetchHealth()).rejects.toMatchObject({
      code: 'network_failure',
      message: 'Backend unavailable. Could not reach the AEGIS API.',
    });
  });

  it('rejects malformed response', () => {
    expect(() => validateSecurityEvent({ event_id: 'broken' })).toThrowError(ApiError);
  });
});
