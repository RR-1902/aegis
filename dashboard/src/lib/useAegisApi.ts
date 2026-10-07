import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from '../api/client';
import { fetchEvent, fetchEvents, fetchHealth } from '../api/events';
import type { HealthResponse, SecurityEvent } from '../types/api';

/** The API's maximum page size (app/api/routes/events.py). */
export const EVENT_LIMIT = 200;

/** After this long the request is probably waiting on a sleeping free-tier host. */
const SLOW_AFTER_MS = 4000;

export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === 'network_failure') {
      return 'The AEGIS API could not be reached. Check that the backend is running, then retry.';
    }
    if (error.code === 'event_not_found') {
      return 'This event is not in the ledger any more. Pick another event from the list.';
    }
    if (error.code === 'invalid_persisted_record') {
      return 'The API returned a record that does not match the security event format.';
    }
    if (error.code === 'storage_unavailable') {
      return 'The API is up but cannot read its event database.';
    }
    return error.message;
  }
  return 'Something unexpected went wrong while talking to the API.';
}

type Remote<T> = {
  data: T | null;
  loading: boolean;
  slow: boolean;
  error: string | null;
};

function useSlowFlag(loading: boolean): boolean {
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    if (!loading) {
      setSlow(false);
      return undefined;
    }
    const timer = window.setTimeout(() => setSlow(true), SLOW_AFTER_MS);
    return () => window.clearTimeout(timer);
  }, [loading]);
  return slow;
}

export type AegisApi = {
  health: Remote<HealthResponse>;
  events: Remote<SecurityEvent[]>;
  syncedAt: string | null;
  refresh: () => void;
};

export function useAegisApi(): AegisApi {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [events, setEvents] = useState<SecurityEvent[] | null>(null);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [eventsLoading, setEventsLoading] = useState(true);
  const [syncedAt, setSyncedAt] = useState<string | null>(null);
  const generation = useRef(0);

  const load = useCallback(() => {
    const current = ++generation.current;
    setHealthLoading(true);
    setEventsLoading(true);
    setHealthError(null);
    setEventsError(null);

    fetchHealth()
      .then((data) => {
        if (current !== generation.current) return;
        setHealth(data);
      })
      .catch((error: unknown) => {
        if (current !== generation.current) return;
        setHealth(null);
        setHealthError(describeError(error));
      })
      .finally(() => {
        if (current === generation.current) setHealthLoading(false);
      });

    fetchEvents({ limit: EVENT_LIMIT })
      .then((data) => {
        if (current !== generation.current) return;
        setEvents(data.items);
        setSyncedAt(new Date().toISOString());
      })
      .catch((error: unknown) => {
        if (current !== generation.current) return;
        setEventsError(describeError(error));
      })
      .finally(() => {
        if (current === generation.current) setEventsLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const healthSlow = useSlowFlag(healthLoading);
  const eventsSlow = useSlowFlag(eventsLoading);

  return {
    health: { data: health, loading: healthLoading, slow: healthSlow, error: healthError },
    events: { data: events, loading: eventsLoading, slow: eventsSlow, error: eventsError },
    syncedAt,
    refresh: load,
  };
}

/**
 * Show the list copy of an event at once, then confirm it against `/events/{id}`.
 */
export function useEventDetail(eventId: string | null, fallback: SecurityEvent | null): Remote<SecurityEvent> {
  const [data, setData] = useState<SecurityEvent | null>(fallback);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!eventId) {
      setData(null);
      setError(null);
      setLoading(false);
      return undefined;
    }
    let cancelled = false;
    setData(fallback);
    setError(null);
    setLoading(true);
    fetchEvent(eventId)
      .then((event) => {
        if (!cancelled) setData(event);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        setData(null);
        setError(describeError(reason));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // The fallback is only a placeholder for the first paint of a new selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventId]);

  return { data, loading, slow: false, error };
}
