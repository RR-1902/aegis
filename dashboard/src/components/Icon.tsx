import type { ReactNode } from 'react';

/**
 * AEGIS icon set. One 24px grid, 1.6px strokes, round joins. Each icon names a concept in
 * the pipeline; the glossary shows them next to their definitions.
 */
const PATHS = {
  packet: (
    <>
      <rect x="3.5" y="6" width="17" height="12" rx="2" />
      <path d="M3.5 10.2h17M7 14h4" />
    </>
  ),
  capture: (
    <>
      <circle cx="12" cy="12" r="1.8" />
      <path d="M8.2 8.2a5.4 5.4 0 0 0 0 7.6M15.8 8.2a5.4 5.4 0 0 1 0 7.6M5.4 5.4a9.3 9.3 0 0 0 0 13.2M18.6 5.4a9.3 9.3 0 0 1 0 13.2" />
    </>
  ),
  filter: <path d="M4 5h16l-6.2 7.2v5.6L10.2 20v-7.8L4 5Z" />,
  layers: (
    <>
      <path d="m12 3.8 8.5 4.4L12 12.6 3.5 8.2 12 3.8Z" />
      <path d="m3.5 12.2 8.5 4.4 8.5-4.4M3.5 16.2l8.5 4.4 8.5-4.4" />
    </>
  ),
  flow: <path d="M3.5 7h11m-3-3 3 3-3 3M3.5 12h15m-3-3 3 3-3 3M3.5 17h8m-3-3 3 3-3 3" />,
  window: (
    <>
      <path d="M7 4H4v16h3M17 4h3v16h-3" />
      <circle cx="12" cy="12" r="3.6" />
      <path d="M12 10.2V12l1.3 1.1" />
    </>
  ),
  features: <path d="M3.5 20h17M6 20v-6M10.3 20V9M14.6 20v-4.5M19 20V5.5" />,
  detect: (
    <>
      <circle cx="12" cy="12" r="6.8" />
      <circle cx="12" cy="12" r="1.6" />
      <path d="M12 2.5v3.2M12 18.3v3.2M2.5 12h3.2M18.3 12h3.2" />
    </>
  ),
  threshold: (
    <>
      <path d="M3 9.5h18" strokeDasharray="2.2 2.2" />
      <path d="m3 18 4.6-4.2 3.6 2.4 4.6-9.6L21 11" />
    </>
  ),
  score: (
    <>
      <path d="M4.2 16.5a8 8 0 1 1 15.6 0" />
      <path d="m12 16.5 4.2-5.2" />
      <circle cx="12" cy="16.5" r="1.3" />
      <path d="M7 20h10" />
    </>
  ),
  policy: (
    <>
      <circle cx="12" cy="4.8" r="1.8" />
      <path d="M12 6.6V10m0 0-6 5.2V20m6-10 6 5.2V20M12 10v10" />
    </>
  ),
  respond: (
    <>
      <path d="M12 3.2 19.5 6v5.4c0 4.6-3.1 8-7.5 9.6-4.4-1.6-7.5-5-7.5-9.6V6L12 3.2Z" />
      <path d="m8.8 12.1 2.2 2.2 4.3-4.4" />
    </>
  ),
  simulate: (
    <>
      <path d="M12 3.2 19.5 6v5.4c0 4.6-3.1 8-7.5 9.6-4.4-1.6-7.5-5-7.5-9.6V6L12 3.2Z" strokeDasharray="2.4 2.2" />
      <path d="M12 9v3.4l2 1.4" />
    </>
  ),
  record: (
    <>
      <ellipse cx="12" cy="6" rx="7.5" ry="2.8" />
      <path d="M4.5 6v6c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8V6M4.5 12v6c0 1.6 3.4 2.8 7.5 2.8s7.5-1.2 7.5-2.8v-6" />
    </>
  ),
  hash: <path d="M9.6 3.8 7.8 20.2M16.2 3.8l-1.8 16.4M4.4 9h16M3.6 15h16" />,
  code: <path d="m8 7.5-4.5 4.5L8 16.5M16 7.5l4.5 4.5-4.5 4.5M13.6 5l-3.2 14" />,
  syn: (
    <>
      <path d="M4 8v8M4 12h14m-4-4 4 4-4 4" />
      <path d="M20.5 8v8" strokeDasharray="1.6 1.9" />
    </>
  ),
  flood: (
    <path d="M3 7.5c2.2-2 4.3 2 6.5 0s4.3 2 6.5 0 3.3 0 5 0M3 12.5c2.2-2 4.3 2 6.5 0s4.3 2 6.5 0 3.3 0 5 0M3 17.5c2.2-2 4.3 2 6.5 0s4.3 2 6.5 0 3.3 0 5 0" />
  ),
  scan: (
    <>
      <circle cx="4.6" cy="12" r="1.6" />
      <path d="m6.2 11.3 7.4-6.1M6.2 11.7l7.4-2.3M6.2 12.3l7.4 2.3M6.2 12.7l7.4 6.1M15.5 5h5M15.5 9.4h5M15.5 14.6h5M15.5 19h5" />
    </>
  ),
  key: (
    <>
      <circle cx="7.5" cy="12" r="3.8" />
      <path d="M11.3 12H21m-3 0v3.2M15 12v2.4" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8.3 10.5V7.8a3.7 3.7 0 0 1 7.4 0v2.7M12 14.2v2.2" />
    </>
  ),
  evidence: (
    <>
      <circle cx="10.5" cy="10.5" r="6" />
      <path d="m15 15 5.5 5.5M8 10.5h5M10.5 8v5" />
    </>
  ),
  level: <path d="M5 19v-3M9.6 19v-6M14.3 19V9.5M19 19V5.5" />,
  observe: (
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  explain: (
    <>
      <path d="M4.5 5h15v10.5H10L5.5 19.5v-4H4.5V5Z" />
      <path d="M8 9h8M8 12.2h5" />
    </>
  ),
  source: (
    <>
      <path d="M12 21s-6.2-5.6-6.2-10.6a6.2 6.2 0 1 1 12.4 0C18.2 15.4 12 21 12 21Z" />
      <circle cx="12" cy="10.4" r="2.2" />
    </>
  ),
  ledger: (
    <>
      <path d="M9 6.5h11M9 12h11M9 17.5h11" />
      <circle cx="5" cy="6.5" r="1.1" />
      <circle cx="5" cy="12" r="1.1" />
      <circle cx="5" cy="17.5" r="1.1" />
    </>
  ),
  test: (
    <path d="M9.5 3.5h5M10.3 3.5V9l-5 8.6a1.8 1.8 0 0 0 1.6 2.9h10.2a1.8 1.8 0 0 0 1.6-2.9l-5-8.6V3.5M7.6 14.5h8.8" />
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  severity: <path d="M12 3.5 21 19.5H3L12 3.5ZM12 9.8v4.4M12 16.8v.1" />,
  arrow: <path d="M4.5 12h15m-5.5-5.5L19.5 12 14 17.5" />,
  external: <path d="M14 4.5h5.5V10M19.5 4.5 11 13M10 6H5.5v12.5H18V14" />,
  copy: (
    <>
      <rect x="8.5" y="8.5" width="11" height="11" rx="1.8" />
      <path d="M15.5 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5" />
    </>
  ),
  refresh: <path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4.2h-4.2" />,
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  cross: <path d="m6.5 6.5 11 11M17.5 6.5l-11 11" />,
  info: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 11v5.5M12 7.8v.1" />
    </>
  ),
  shield: <path d="M12 3.2 19.5 6v5.4c0 4.6-3.1 8-7.5 9.6-4.4-1.6-7.5-5-7.5-9.6V6L12 3.2Z" />,
  server: (
    <>
      <rect x="4" y="4.5" width="16" height="6.5" rx="1.6" />
      <rect x="4" y="13" width="16" height="6.5" rx="1.6" />
      <path d="M7.5 7.75h.01M7.5 16.25h.01M11 7.75h5.5M11 16.25h5.5" />
    </>
  ),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;

type IconProps = {
  name: IconName;
  size?: number;
  className?: string;
  title?: string;
};

export default function Icon({ name, size = 20, className, title }: IconProps) {
  return (
    <svg
      className={className ? `icon ${className}` : 'icon'}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      role={title ? 'img' : undefined}
      aria-label={title}
      aria-hidden={title ? undefined : true}
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}
