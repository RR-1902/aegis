import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import EventDetails from './EventDetails';
import type { SecurityEvent } from '../types/api';

const event: SecurityEvent = {
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
    flow_key: null,
    window_start: null,
    window_end: null,
    detections: [],
    explanation: 'Combined score exceeded critical threshold.',
  },
  policy: {
    recommended_action: 'block_source',
    allowed: false,
    execution_mode: 'simulate',
    flow_key: null,
    window_start: null,
    window_end: null,
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

describe('EventDetails', () => {
  it('renders detection, evidence, risk, policy, and response', () => {
    render(<EventDetails event={event} loading={false} error={null} />);

    expect(screen.getByText('Event Identity')).toBeInTheDocument();
    expect(screen.getByText('Detection')).toBeInTheDocument();
    expect(screen.getByText('Risk')).toBeInTheDocument();
    expect(screen.getByText('Policy')).toBeInTheDocument();
    expect(screen.getByText('Response')).toBeInTheDocument();
    expect(screen.getByText('High SYN rate observed.')).toBeInTheDocument();
    expect(screen.getByText('Combined score exceeded critical threshold.')).toBeInTheDocument();
    expect(screen.getByText('Simulation only.')).toBeInTheDocument();
    expect(screen.getByText('No system state changed.')).toBeInTheDocument();
  });

  it('does not claim a fake SAFE_MODE toggle', () => {
    render(<EventDetails event={event} loading={false} error={null} />);

    expect(screen.queryByText(/safe mode/i)).not.toBeInTheDocument();
  });
});
