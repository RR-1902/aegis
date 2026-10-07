import { useEffect, useLayoutEffect, useRef, type RefObject } from 'react';
import Lenis from 'lenis';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);

export { gsap, ScrollTrigger };

let lenis: Lenis | null = null;

export function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/**
 * Lenis smooth scrolling driven by the GSAP ticker, so ScrollTrigger and Lenis share one
 * animation frame. Skipped entirely when the visitor prefers reduced motion.
 */
export function useSmoothScroll(): void {
  useEffect(() => {
    if (prefersReducedMotion()) return undefined;
    document.documentElement.classList.add('has-motion');

    const instance = new Lenis({ lerp: 0.1, smoothWheel: true, wheelMultiplier: 0.9 });
    lenis = instance;
    instance.on('scroll', ScrollTrigger.update);
    const tick = (time: number) => instance.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);

    return () => {
      gsap.ticker.remove(tick);
      instance.destroy();
      lenis = null;
      document.documentElement.classList.remove('has-motion');
    };
  }, []);
}

/** Scroll to an element or a pixel offset, smoothly when Lenis is running. */
export function scrollToTarget(target: HTMLElement | number, options: { offset?: number; immediate?: boolean } = {}): void {
  const offset = options.offset ?? -88;
  if (lenis) {
    lenis.scrollTo(target, { offset: typeof target === 'number' ? 0 : offset, immediate: options.immediate });
    return;
  }
  const top = typeof target === 'number' ? target : target.getBoundingClientRect().top + window.scrollY + offset;
  window.scrollTo({ top, behavior: options.immediate || prefersReducedMotion() ? 'auto' : 'smooth' });
}

/** Stop and start Lenis, for overlays that need the page held still. */
export function setScrollLocked(locked: boolean): void {
  if (!lenis) return;
  if (locked) lenis.stop();
  else lenis.start();
}

/**
 * Reveal every `[data-reveal]` and split heading inside `scope` as it scrolls into view.
 * Only transform and opacity animate.
 */
export function useReveals(scope: RefObject<HTMLElement>, deps: unknown[] = []): void {
  useLayoutEffect(() => {
    const root = scope.current;
    if (!root || prefersReducedMotion()) return undefined;

    const context = gsap.context(() => {
      const revealed = root.querySelectorAll<HTMLElement>('[data-reveal]');
      gsap.set(revealed, { opacity: 0, y: 32, yPercent: 0 });
      ScrollTrigger.batch(revealed, {
        start: 'top 88%',
        once: true,
        onEnter: (batch) =>
          gsap.to(batch, {
            opacity: 1,
            y: 0,
            duration: 0.9,
            ease: 'power3.out',
            stagger: 0.08,
            overwrite: true,
          }),
      });

      root.querySelectorAll<HTMLElement>('[data-split]').forEach((heading) => {
        const words = heading.querySelectorAll<HTMLElement>('.word__inner');
        // fromTo with explicit y: 0 clears any pixel offset GSAP cached from an earlier mount.
        gsap.fromTo(
          words,
          { yPercent: 115, y: 0 },
          {
            yPercent: 0,
            y: 0,
            duration: 1.05,
            ease: 'expo.out',
            stagger: 0.045,
            clearProps: 'transform',
            scrollTrigger: { trigger: heading, start: 'top 90%', once: true },
          },
        );
      });

      root.querySelectorAll<HTMLElement>('[data-count]').forEach((element) => {
        const target = Number(element.dataset.count);
        const decimals = Number(element.dataset.decimals ?? 0);
        const state = { value: 0 };
        gsap.to(state, {
          value: target,
          duration: 1.6,
          ease: 'power2.out',
          scrollTrigger: { trigger: element, start: 'top 92%', once: true },
          onUpdate: () => {
            element.textContent = state.value.toFixed(decimals);
          },
        });
      });
    }, root);

    // Layout shifts after fonts load would leave trigger positions stale.
    void document.fonts?.ready.then(() => ScrollTrigger.refresh());

    return () => context.revert();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

/** Pause infinite CSS animations inside an element while it is off screen. */
export function usePauseOffscreen<T extends HTMLElement>(): RefObject<T> {
  const ref = useRef<T>(null);
  useEffect(() => {
    const element = ref.current;
    if (!element || typeof IntersectionObserver === 'undefined') return undefined;
    const observer = new IntersectionObserver(([entry]) => {
      element.classList.toggle('is-offscreen', !entry.isIntersecting);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return ref;
}
