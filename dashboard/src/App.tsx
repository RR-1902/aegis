import { useEffect, useRef } from 'react';
import Footer from './components/Footer';
import TopBar from './components/TopBar';
import Overview from './components/landing/Overview';
import Ledger from './components/ledger/Ledger';
import { scrollToTarget, useSmoothScroll } from './lib/motion';
import { useRoute } from './lib/route';
import { useAegisApi } from './lib/useAegisApi';

export default function App() {
  useSmoothScroll();
  const api = useAegisApi();
  const [route, navigate] = useRoute();
  const previousPage = useRef(route.page);
  const firstRender = useRef(true);

  // A new page starts at the top; an anchor on the overview glides to its section.
  useEffect(() => {
    const pageChanged = previousPage.current !== route.page;
    const initial = firstRender.current;
    previousPage.current = route.page;
    firstRender.current = false;
    if (route.page === 'overview' && route.anchor) {
      const target = document.getElementById(route.anchor);
      if (target) {
        // Wait a frame so a freshly mounted page has laid out.
        requestAnimationFrame(() => scrollToTarget(target, { immediate: initial }));
      }
    } else if (pageChanged) {
      scrollToTarget(0, { immediate: true });
    }
  }, [route]);

  const mainId = route.page === 'ledger' ? 'main' : 'overview';

  return (
    <div className="app">
      <a
        className="skip-link"
        href={`#${mainId}`}
        onClick={(event) => {
          event.preventDefault();
          document.getElementById(mainId)?.focus();
        }}
      >
        Skip to content
      </a>
      <TopBar page={route.page} health={api.health} />
      {route.page === 'ledger' ? (
        <Ledger api={api} params={route.params} navigate={navigate} />
      ) : (
        <Overview api={api} />
      )}
      <Footer version={api.health.data?.app_version ?? null} />
    </div>
  );
}
