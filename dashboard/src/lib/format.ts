import type { FlowKey } from '../types/api';

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium', hourCycle: 'h23' });
const clock = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const day = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
const decimal = new Intl.NumberFormat(undefined, { maximumFractionDigits: 3 });

function parse(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value: string | null | undefined): string {
  const date = parse(value);
  if (!date) return value ?? '—';
  return dateTime.format(date);
}

export function formatClock(value: string | null | undefined): string {
  const date = parse(value);
  return date ? clock.format(date) : '—';
}

export function formatDay(value: string | null | undefined): string {
  const date = parse(value);
  return date ? day.format(date) : '—';
}

export function windowSeconds(start: string | null | undefined, end: string | null | undefined): number | null {
  const from = parse(start);
  const to = parse(end);
  if (!from || !to) return null;
  return Math.round((to.getTime() - from.getTime()) / 100) / 10;
}

export function formatWindow(start: string | null | undefined, end: string | null | undefined): string {
  return `${formatClock(start)}–${formatClock(end)}`;
}

const RELATIVE_STEPS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 31_536_000],
  ['month', 2_592_000],
  ['day', 86_400],
  ['hour', 3_600],
  ['minute', 60],
];

export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  const date = parse(value);
  if (!date) return '—';
  const seconds = Math.round((date.getTime() - now) / 1000);
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(seconds) >= size) {
      return relative.format(Math.round(seconds / size), unit);
    }
  }
  return 'just now';
}

export function formatEndpoint(ip: string, port: number | null): string {
  return port === null ? ip : `${ip}:${port}`;
}

export function formatFlow(flowKey: FlowKey): string {
  return `${formatEndpoint(flowKey.src_ip, flowKey.src_port)} → ${formatEndpoint(flowKey.dst_ip, flowKey.dst_port)} ${flowKey.protocol}`;
}

/** `block_source` → `Block source`. */
export function humanize(value: string): string {
  const words = value.replace(/[_-]+/g, ' ').trim().toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** `security-event:a052b98a…` → `a052b98a…7b56`. */
export function shortEventId(eventId: string): string {
  const hash = eventId.replace(/^security-event:/, '');
  return hash.length > 14 ? `${hash.slice(0, 8)}…${hash.slice(-4)}` : hash;
}

export function formatNumber(value: number): string {
  return decimal.format(value);
}

const DOCUMENTATION_NETS = ['192.0.2.', '198.51.100.', '203.0.113.'];

/** RFC 5737 documentation addresses never appear on a real network; AEGIS simulations use them. */
export function isSyntheticSource(ip: string): boolean {
  return DOCUMENTATION_NETS.some((prefix) => ip.startsWith(prefix));
}
