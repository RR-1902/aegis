import { useId, type ReactNode } from 'react';
import { GLOSSARY_BY_ID } from '../lib/glossary';
import Icon from './Icon';

/** An inline term with a short definition on hover, focus or tap. */
export default function Term({ id, children }: { id: string; children?: ReactNode }) {
  const entry = GLOSSARY_BY_ID[id];
  const tipId = useId();
  if (!entry) return <>{children}</>;
  return (
    <span className="term">
      {/* A focusable span rather than a button, so punctuation after a term never wraps onto its own line. */}
      <span className="term__trigger" tabIndex={0} aria-describedby={tipId}>
        {children ?? entry.term}
      </span>
      <span className="term__tip" role="tooltip" id={tipId}>
        <span className="term__tip-head">
          <Icon name={entry.icon} size={16} />
          {entry.term}
        </span>
        {entry.short}
      </span>
    </span>
  );
}
