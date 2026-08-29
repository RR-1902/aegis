import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import EventsTable from './EventsTable';
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

describe('EventsTable', () => {
  it('renders an actual event with badges', () => {
    render(
      <EventsTable
        events={[event]}
        selectedEventId={null}
        onSelect={vi.fn()}
        loading={false}
        error={null}
        filtersApplied={false}
      />,
    );

    expect(screen.getByText('SYN Flood')).toBeInTheDocument();
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('Simulated')).toBeInTheDocument();
  });

  it('shows empty result state', () => {
    render(
      <EventsTable
        events={[]}
        selectedEventId={null}
        onSelect={vi.fn()}
        loading={false}
        error={null}
        filtersApplied={false}
      />,
    );

    expect(screen.getByText('No security events recorded.')).toBeInTheDocument();
  });

  it('selects a row', () => {
    const onSelect = vi.fn();
    render(
      <EventsTable
        events={[event]}
        selectedEventId={null}
        onSelect={onSelect}
        loading={false}
        error={null}
        filtersApplied={false}
      />,
    );

    fireEvent.click(screen.getByRole('button'));
    expect(onSelect).toHaveBeenCalledWith(event);
  });
});
