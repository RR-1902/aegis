export type RingState = 'waiting' | 'ok' | 'down';

/** Bordered status ring: dashed while waiting, filled centre when reachable, crossed when not. */
export default function StatusRing({ state }: { state: RingState }) {
  return (
    <svg className={`ring ring--${state}`} width="14" height="14" viewBox="0 0 14 14" aria-hidden="true" focusable="false">
      <circle className="ring__outline" cx="7" cy="7" r="5.75" fill="none" strokeWidth="1.5" />
      {state === 'ok' && <circle className="ring__core" cx="7" cy="7" r="2.4" />}
      {state === 'down' && <path className="ring__cross" d="M5 5l4 4M9 5l-4 4" strokeWidth="1.5" strokeLinecap="round" />}
    </svg>
  );
}
