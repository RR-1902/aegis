import { useCallback, useEffect, useState } from 'react';

/**
 * Hash routing so the build works on any static host (Vercel, or the FastAPI static mount)
 * without server rewrites.
 *   #/ledger?risk=high&status=no_action&event=<id>   the event ledger
 *   #how-it-works                                     an anchor on the overview
 */
export type Route =
  | { page: 'overview'; anchor: string | null }
  | { page: 'ledger'; params: URLSearchParams };

export function parseRoute(hash: string): Route {
  const value = hash.replace(/^#/, '');
  if (value.startsWith('/ledger')) {
    const query = value.split('?')[1] ?? '';
    return { page: 'ledger', params: new URLSearchParams(query) };
  }
  return { page: 'overview', anchor: value && !value.startsWith('/') ? value : null };
}

export function ledgerHref(params: Record<string, string | null | undefined> = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) search.set(key, value);
  }
  const query = search.toString();
  return query ? `#/ledger?${query}` : '#/ledger';
}

export function useRoute(): [Route, (href: string, options?: { replace?: boolean }) => void] {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));

  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener('hashchange', onChange);
    window.addEventListener('popstate', onChange);
    return () => {
      window.removeEventListener('hashchange', onChange);
      window.removeEventListener('popstate', onChange);
    };
  }, []);

  const navigate = useCallback((href: string, options?: { replace?: boolean }) => {
    if (options?.replace) {
      window.history.replaceState(null, '', href);
    } else {
      window.history.pushState(null, '', href);
    }
    setRoute(parseRoute(window.location.hash));
  }, []);

  return [route, navigate];
}
