import { useCallback, useEffect, useMemo, useState } from 'react';
import Header from './components/Header';
import StatusBar from './components/StatusBar';
import SummaryPanel from './components/SummaryPanel';
import EventFilters from './components/EventFilters';
import EventsTable from './components/EventsTable';
import EventDetails from './components/EventDetails';
import MockAttackToolbar from './components/MockAttackToolbar';
import TacticalNav from './components/landing/TacticalNav';
import AegisLandingPage from './components/landing/AegisLandingPage';
import AegisExplainerPage from './components/docs/AegisExplainerPage';
import { fetchEvent, fetchEvents, fetchHealth } from './api/events';
import type { EventFilters as EventFiltersType, HealthResponse, SecurityEvent } from './types/api';
import { ApiError } from './api/client';

const DEFAULT_LIMIT = 50;

function mapUiError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'network_failure') {
      return 'Backend unavailable. Could not reach the AEGIS API.';
    }
    if (error.code === 'event_not_found') {
      return 'The selected security event could not be found.';
    }
    if (error.code === 'invalid_persisted_record') {
      return 'The API returned an invalid security event record.';
    }
    return error.message;
  }
  return 'The AEGIS dashboard encountered an unexpected error.';
}

export default function App() {
  const [view, setView] = useState<'landing' | 'console' | 'docs'>('landing');
  const [scanlinesActive, setScanlinesActive] = useState(true);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);

  const [filters, setFilters] = useState<EventFiltersType>({ limit: DEFAULT_LIMIT });
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [eventsError, setEventsError] = useState<string | null>(null);

  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);

  const [lastRefresh, setLastRefresh] = useState<string | null>(null);

  const refreshHealth = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const data = await fetchHealth();
      setHealth(data);
    } catch (error) {
      setHealthError(mapUiError(error));
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  const refreshEvents = useCallback(async (activeFilters: EventFiltersType) => {
    setEventsLoading(true);
    setEventsError(null);
    try {
      const data = await fetchEvents(activeFilters);
      setEvents(data.items);
      setLastRefresh(new Date().toISOString());

      if (selectedEventId && !data.items.some((event) => event.event_id === selectedEventId)) {
        setSelectedEventId(null);
        setSelectedEvent(null);
        setDetailsError(null);
      }
    } catch (error) {
      setEventsError(mapUiError(error));
      setEvents([]);
    } finally {
      setEventsLoading(false);
    }
  }, [selectedEventId]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshHealth(), refreshEvents(filters)]);
  }, [filters, refreshEvents, refreshHealth]);

  useEffect(() => {
    void refreshHealth();
  }, [refreshHealth]);

  useEffect(() => {
    void refreshEvents(filters);
  }, [filters, refreshEvents]);

  const handleSelectEvent = useCallback(async (event: SecurityEvent) => {
    setSelectedEventId(event.event_id);
    setDetailsLoading(true);
    setDetailsError(null);
    try {
      const fullEvent = await fetchEvent(event.event_id);
      setSelectedEvent(fullEvent);
    } catch (error) {
      setSelectedEvent(null);
      setDetailsError(mapUiError(error));
    } finally {
      setDetailsLoading(false);
    }
  }, []);

  const handleInjectMockEvent = useCallback((mockEvent: SecurityEvent) => {
    setEvents((prev) => [mockEvent, ...prev]);
    setSelectedEventId(mockEvent.event_id);
    setSelectedEvent(mockEvent);
    setDetailsError(null);
    setLastRefresh(new Date().toISOString());
  }, []);

  const filtersApplied = useMemo(() => Boolean(filters.risk_level || filters.lifecycle_status), [filters]);

  return (
    <div className="bg-black text-neutral-100 min-h-screen relative font-mono">
      {/* CRT Scanlines and Vignette Shaders */}
      {scanlinesActive && (
        <>
          <div className="crt-overlay" />
          <div className="crt-vignette" />
        </>
      )}

      {/* Sticky Tactical HUD Navigation */}
      <TacticalNav
        currentView={view}
        onViewChange={setView}
        scanlinesActive={scanlinesActive}
        onToggleScanlines={() => setScanlinesActive((prev) => !prev)}
      />

      {/* Main Content Area */}
      {view === 'docs' ? (
        <AegisExplainerPage
          onBackToLanding={() => setView('landing')}
          onLaunchConsole={() => setView('console')}
        />
      ) : view === 'landing' ? (
        <>
          <AegisLandingPage onLaunchConsole={() => setView('console')} />

          {/* Integrated Live Security Operations Console section at the bottom of Landing Page */}
          <div id="live-console-grid" className="section-wrapper" style={{ paddingTop: 40 }}>
            <div className="section-header">
              <span className="section-index">06 // LIVE OPERATIONS CONSOLE</span>
              <h2 className="section-heading">PERSISTED SECURITY EVENT LEDGER</h2>
              <p className="section-subtext">
                Direct real-time telemetry feed from the AEGIS SQLite event database and FastAPI REST endpoints.
              </p>
            </div>

            <main className="app-shell" style={{ padding: 0 }}>
              <Header />
              <StatusBar health={health} healthError={healthError} lastRefresh={lastRefresh} loading={healthLoading} />
              
              {/* Interactive Mock Attack Injection Toolbar */}
              <MockAttackToolbar onInjectEvent={handleInjectMockEvent} />

              <SummaryPanel events={events} />

              <section className="main-grid">
                <div className="left-column">
                  <EventFilters
                    filters={filters}
                    onChange={(next) => setFilters({ ...next, limit: DEFAULT_LIMIT })}
                    onRefresh={() => void refreshAll()}
                    loading={eventsLoading || healthLoading}
                  />
                  <EventsTable
                    events={events}
                    selectedEventId={selectedEventId}
                    onSelect={(event) => void handleSelectEvent(event)}
                    loading={eventsLoading}
                    error={eventsError}
                    filtersApplied={filtersApplied}
                  />
                </div>

                <EventDetails event={selectedEvent} loading={detailsLoading} error={detailsError} />
              </section>
            </main>
          </div>
        </>
      ) : (
        /* Focused Full-Width Operations Console Mode */
        <main className="app-shell" style={{ marginTop: 24 }}>
          <Header />
          <StatusBar health={health} healthError={healthError} lastRefresh={lastRefresh} loading={healthLoading} />

          {/* Interactive Mock Attack Injection Toolbar */}
          <MockAttackToolbar onInjectEvent={handleInjectMockEvent} />

          <SummaryPanel events={events} />

          <section className="main-grid">
            <div className="left-column">
              <EventFilters
                filters={filters}
                onChange={(next) => setFilters({ ...next, limit: DEFAULT_LIMIT })}
                onRefresh={() => void refreshAll()}
                loading={eventsLoading || healthLoading}
              />
              <EventsTable
                events={events}
                selectedEventId={selectedEventId}
                onSelect={(event) => void handleSelectEvent(event)}
                loading={eventsLoading}
                error={eventsError}
                filtersApplied={filtersApplied}
              />
            </div>

            <EventDetails event={selectedEvent} loading={detailsLoading} error={detailsError} />
          </section>
        </main>
      )}
    </div>
  );
}

