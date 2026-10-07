import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { ApiError } from './api/client';
import * as api from './api/events';
import type { HealthResponse, SecurityEvent, SimulationsResponse } from './types/api';

const health: HealthResponse = { status: 'ok', app_name: 'AEGIS', app_version: '0.1.0', database: 'ok' };

const flowKey = { src_ip: '203.0.113.201', dst_ip: '10.0.0.4', protocol: 'TCP', src_port: null, dst_port: null };
const window = { window_start: '2026-10-07T12:00:00Z', window_end: '2026-10-07T12:00:05Z' };

const event: SecurityEvent = {
  event_id: 'security-event:7fcfe2613b9df2233af704589dbd0b2b2eb855784a035ef3dbd40b8d4e156cac',
  flow_key: flowKey,
  ...window,
  recorded_at: '2026-10-07T12:00:06Z',
  detections: [
    {
      rule_id: 'port_scan',
      rule_name: 'Port Scan',
      severity: 'high',
      flow_key: flowKey,
      ...window,
      evidence: {
        features: { unique_destination_ports: 24, syn_rate: 30 },
        thresholds: { port_scan_threshold: 20 },
        comparisons: { 'unique_destination_ports >= port_scan_threshold': true },
      },
      explanation: '24 unique destination ports were observed.',
    },
    {
      rule_id: 'syn_flood',
      rule_name: 'SYN Flood',
      severity: 'high',
      flow_key: flowKey,
      ...window,
      evidence: { features: { syn_rate: 30 }, thresholds: { syn_rate_threshold: 10 }, comparisons: { 'syn_rate >= syn_rate_threshold': true } },
      explanation: 'SYN flood indicators were observed.',
    },
  ],
  risk: { score: 95, level: 'critical', flow_key: flowKey, ...window, detections: [], explanation: 'Heuristic risk score 95/100.' },
  policy: {
    recommended_action: 'alert_only',
    allowed: true,
    execution_mode: 'none',
    flow_key: flowKey,
    ...window,
    risk_score: 95,
    risk_level: 'critical',
    detection_ids: ['port_scan', 'syn_flood'],
    target: null,
    explanation: 'Automatic blocking was not authorized.',
  },
  response: {
    action: 'alert_only',
    status: 'no_action',
    simulated: false,
    target: null,
    message: 'No external action taken for ALERT_ONLY.',
    error: null,
    timestamp: '2026-10-07T12:00:06Z',
  },
  lifecycle_status: 'no_action',
};

const simulations: SimulationsResponse = {
  enabled: true,
  scenarios: [
    { id: 'syn_flood', name: 'SYN flood', summary: '60 SYN packets.', flow_key_strategy: 'five_tuple', target: '10.0.0.1' },
    { id: 'benign', name: 'Normal DNS lookups', summary: 'Five DNS queries.', flow_key_strategy: 'five_tuple', target: '10.0.0.53' },
  ],
};

function mockApi({ events = [event] }: { events?: SecurityEvent[] } = {}) {
  vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
  const fetchEvents = vi.spyOn(api, 'fetchEvents').mockResolvedValue({ items: events, count: events.length, limit: 200 });
  const fetchEvent = vi.spyOn(api, 'fetchEvent').mockResolvedValue(event);
  vi.spyOn(api, 'fetchSimulations').mockResolvedValue(simulations);
  return { fetchEvents, fetchEvent };
}

/** Start on the ledger route, so no overview content is ever on screen. */
function renderLedger(query = '') {
  globalThis.window.location.hash = `#/ledger${query}`;
  return render(<App />);
}

describe('overview', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('explains what AEGIS is and reports the API status', async () => {
    mockApi();
    render(<App />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Detect the attack.');
    expect(screen.getByRole('heading', { name: 'What is AEGIS?' })).toBeInTheDocument();
    expect(await screen.findByText('API online')).toBeInTheDocument();
  });

  it('shows the latest stored event as a decision chain', async () => {
    mockApi();
    render(<App />);
    const chain = await screen.findByRole('list', { name: 'Decision chain' });
    expect(within(chain).getByText('Port Scan + SYN Flood')).toBeInTheDocument();
    expect(within(chain).getByText('Alert only')).toBeInTheDocument();
  });

  it('explains a term on focus', async () => {
    mockApi();
    render(<App />);
    const term = screen.getAllByText('SYN floods')[0];
    expect(term).toHaveAttribute('aria-describedby');
    const tip = document.getElementById(term.getAttribute('aria-describedby') ?? '');
    expect(tip).toHaveTextContent('denial-of-service');
  });

  it('runs a simulation and reports what the engine stored', async () => {
    const user = userEvent.setup();
    mockApi();
    vi.spyOn(api, 'runSimulation').mockResolvedValue({
      scenario: simulations.scenarios[0],
      source_ip: '198.51.100.44',
      packets: 60,
      stored: 1,
      events: [event],
    });
    render(<App />);
    const card = await screen.findByRole('button', { name: /SYN flood.*60 SYN packets/ });
    await waitFor(() => expect(card).toBeEnabled());
    await user.click(card);
    expect(await screen.findByText(/60 synthetic packets from/)).toBeInTheDocument();
    expect(api.runSimulation).toHaveBeenCalledWith('syn_flood');
  });

  it('says when the API cannot run simulations', async () => {
    mockApi();
    vi.spyOn(api, 'fetchSimulations').mockRejectedValue(new ApiError('Not Found', 'http_404', 404));
    render(<App />);
    expect(await screen.findByText(/older version without simulations/)).toBeInTheDocument();
  });
});

describe('event ledger', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('lists events and shows an empty prompt in the inspector', async () => {
    mockApi();
    renderLedger();
    expect(await screen.findByRole('heading', { name: 'Event ledger' })).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: /Port Scan \+ SYN Flood/ })).toBeInTheDocument();
    expect(screen.getByText('Select an event to see how AEGIS reached its verdict.')).toBeInTheDocument();
  });

  it('opens the full decision chain for a selected event', async () => {
    const user = userEvent.setup();
    const { fetchEvent } = mockApi();
    renderLedger();
    await user.click(await screen.findByRole('link', { name: /Port Scan \+ SYN Flood/ }));
    const inspector = await screen.findByRole('article');
    expect(within(inspector).getByText('Flow window')).toBeInTheDocument();
    expect(within(inspector).getAllByText('Threshold checks')).toHaveLength(2);
    expect(within(inspector).getByText(/documentation address/)).toBeInTheDocument();
    expect(fetchEvent).toHaveBeenCalledWith(event.event_id);
  });

  it('filters by risk level through the address bar', async () => {
    const user = userEvent.setup();
    mockApi();
    renderLedger();
    await screen.findByRole('link', { name: /Port Scan \+ SYN Flood/ });
    await user.click(screen.getByRole('radio', { name: /Low/ }));
    expect(globalThis.window.location.hash).toContain('risk=low');
    expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();
  });

  it('explains a missing event', async () => {
    mockApi();
    vi.spyOn(api, 'fetchEvent').mockRejectedValue(new ApiError('Not found', 'event_not_found', 404));
    renderLedger(`?event=${encodeURIComponent(event.event_id)}`);
    expect(await screen.findByText(/not in the ledger any more/)).toBeInTheDocument();
  });

  it('explains an unreachable API and offers a retry', async () => {
    vi.spyOn(api, 'fetchHealth').mockResolvedValue(health);
    vi.spyOn(api, 'fetchSimulations').mockResolvedValue(simulations);
    vi.spyOn(api, 'fetchEvents').mockRejectedValue(
      new ApiError('Backend unavailable. Could not reach the AEGIS API.', 'network_failure'),
    );
    renderLedger();
    expect(await screen.findByText(/could not be reached/)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Retry' }).length).toBeGreaterThan(0);
  });
});
