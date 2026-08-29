import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { ApiError } from './api/client';
import * as api from './api/events';
import type { HealthResponse, SecurityEvent } from './types/api';

const health: HealthResponse = {
  status: 'ok',
  app_name: 'AEGIS',
  app_version: '0.1.0',
  database: 'ok',
};

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

describe('App', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('shows initial loading then empty events', async () => {
    vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
    vi.spyOn(api, 'fetchEvents').mockResolvedValue({ items: [], count: 0, limit: 50 });
    vi.spyOn(api, 'fetchEvent').mockResolvedValue(event);

    render(<App />);

    expect(screen.getAllByText('Loading health...')).toHaveLength(2);
    await screen.findByText('No security events recorded.');
  });

  it('shows health error', async () => {
    vi.spyOn(api, 'fetchHealth').mockRejectedValue(
      new ApiError('Backend unavailable. Could not reach the AEGIS API.', 'network_failure'),
    );
    vi.spyOn(api, 'fetchEvents').mockResolvedValue({ items: [], count: 0, limit: 50 });

    render(<App />);

    await screen.findByText('Backend unavailable');
  });

  it('supports filters and refresh', async () => {
    const user = userEvent.setup();
    const fetchHealth = vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
    const fetchEvents = vi.spyOn(api, 'fetchEvents').mockResolvedValue({ items: [event], count: 1, limit: 50 });
    vi.spyOn(api, 'fetchEvent').mockResolvedValue(event);

    render(<App />);

    await screen.findByText('SYN Flood');
    await user.selectOptions(screen.getByLabelText('Risk level'), 'critical');

    await waitFor(() => {
      expect(fetchEvents).toHaveBeenCalled();
    });

    await user.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() => {
      expect(fetchHealth).toHaveBeenCalled();
      expect(fetchEvents).toHaveBeenCalled();
    });
  });

  it('supports event selection and detail fetch', async () => {
    const user = userEvent.setup();
    vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
    vi.spyOn(api, 'fetchEvents').mockResolvedValue({ items: [event], count: 1, limit: 50 });
    vi.spyOn(api, 'fetchEvent').mockResolvedValue(event);

    render(<App />);

    await screen.findByText('SYN Flood');
    await user.click(screen.getByRole('button', { name: /security-event:test/i }));

    await screen.findByText('Event Identity');
    expect(screen.getByText('Detection → Risk → Policy → Response')).toBeInTheDocument();
  });

  it('handles event-not-found', async () => {
    const user = userEvent.setup();
    vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
    vi.spyOn(api, 'fetchEvents').mockResolvedValue({ items: [event], count: 1, limit: 50 });
    vi.spyOn(api, 'fetchEvent').mockRejectedValue(
      new ApiError('The selected security event could not be found.', 'event_not_found'),
    );

    render(<App />);

    await screen.findByText('SYN Flood');
    await user.click(screen.getByRole('button', { name: /security-event:test/i }));

    await screen.findByText('The selected security event could not be found.');
  });

  it('handles backend unavailable for events', async () => {
    vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
    vi.spyOn(api, 'fetchEvents').mockRejectedValue(
      new ApiError('Backend unavailable. Could not reach the AEGIS API.', 'network_failure'),
    );

    render(<App />);

    await screen.findByText('Backend unavailable. Could not reach the AEGIS API.');
  });
});
