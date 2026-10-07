import { useId } from 'react';

type MarkProps = {
  size?: number;
  className?: string;
};

/** The AEGIS mark: a faceted shield carrying an A whose crossbar is a detection line. */
export default function Mark({ size = 28, className }: MarkProps) {
  const id = useId().replace(/:/g, '');
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={`${id}-face`} x1="12" y1="6" x2="54" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#A9CBFF" />
          <stop offset="0.55" stopColor="#5B8DFF" />
          <stop offset="1" stopColor="#2A4FE0" />
        </linearGradient>
      </defs>
      <path d="M32 4 54 12.4V30c0 14-9.4 24.4-22 29.6C19.4 54.4 10 44 10 30V12.4L32 4Z" fill={`url(#${id}-face)`} />
      <path d="M32 4v55.6C19.4 54.4 10 44 10 30V12.4L32 4Z" fill="#04060B" fillOpacity="0.18" />
      <path d="M22.5 45 32 18.5 41.5 45" fill="none" stroke="#050913" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M26.3 35.4h11.4" stroke="#050913" strokeWidth="4.2" strokeLinecap="round" />
    </svg>
  );
}
