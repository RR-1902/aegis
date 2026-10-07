import type { ReactNode } from 'react';
import Icon, { type IconName } from '../Icon';
import Split from './Split';

type SectionHeadProps = {
  id: string;
  label: string;
  icon: IconName;
  title: string;
  children?: ReactNode;
  align?: 'start' | 'center';
};

/** Section opener: a small labelled icon, a split headline and an optional lead paragraph. */
export default function SectionHead({ id, label, icon, title, children, align = 'start' }: SectionHeadProps) {
  return (
    <header className={`section-head section-head--${align}`}>
      <p className="section-head__label" data-reveal="">
        <span className="section-head__icon">
          <Icon name={icon} size={16} />
        </span>
        {label}
      </p>
      <Split as="h2" id={id} className="section-head__title" text={title} />
      {children && (
        <div className="section-head__lead" data-reveal="">
          {children}
        </div>
      )}
    </header>
  );
}
