import { forwardRef, type AnchorHTMLAttributes, type MouseEvent } from 'react';
import { scrollToTarget } from '../../lib/motion';

/**
 * An in-page link that glides to its section with Lenis and keeps the address bar in step.
 * Falls back to a normal anchor jump without JavaScript.
 */
const SectionLink = forwardRef<HTMLAnchorElement, AnchorHTMLAttributes<HTMLAnchorElement>>(function SectionLink(
  { href = '#', onClick, ...props },
  ref,
) {
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    const target = document.getElementById(href.replace(/^#/, ''));
    if (!target) return;
    event.preventDefault();
    window.history.pushState(null, '', href);
    scrollToTarget(target);
  };
  return <a ref={ref} href={href} onClick={handleClick} {...props} />;
});

export default SectionLink;
