import { humanize } from '../lib/format';
import Icon from './Icon';

/** Risk level or rule severity, coloured by level. */
export function LevelTag({ level }: { level: string }) {
  const value = level.toLowerCase();
  return (
    <span className="tag tag--level" data-level={value}>
      {humanize(value)}
    </span>
  );
}

/**
 * Response outcome. The outline carries the meaning: solid for no action,
 * dashed for simulated, struck through for rejected.
 */
export function OutcomeTag({ status }: { status: string }) {
  const value = status.toLowerCase();
  return (
    <span className="tag tag--outcome" data-outcome={value}>
      {humanize(value)}
    </span>
  );
}

/** Marks events whose source is an RFC 5737 documentation address, i.e. a simulation. */
export function SyntheticTag() {
  return (
    <span
      className="synthetic"
      title="The source is an RFC 5737 documentation address, which never appears on a real network: this event came from a simulation."
    >
      <Icon name="simulate" size={14} />
      Synthetic traffic
    </span>
  );
}
