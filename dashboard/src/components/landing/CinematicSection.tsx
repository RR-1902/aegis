import React, { useEffect, useRef, useState } from 'react';

type Props = {
  id: string;
  className?: string;
  locatorTag?: string;
  children: React.ReactNode;
};

export const CinematicSection: React.FC<Props> = ({ id, className = '', locatorTag, children }) => {
  const sectionRef = useRef<HTMLElement | null>(null);
  const [isRevealed, setIsRevealed] = useState(false);

  useEffect(() => {
    const el = sectionRef.current;
    if (!el) return;

    if (typeof IntersectionObserver === 'undefined') {
      setIsRevealed(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsRevealed(true);
          observer.unobserve(entry.target);
        }
      },
      {
        threshold: 0.08,
        rootMargin: '0px 0px -40px 0px',
      }
    );

    observer.observe(el);

    return () => {
      observer.disconnect();
    };
  }, []);

  return (
    <section
      id={id}
      ref={sectionRef}
      className={`cinematic-section ${isRevealed ? 'is-revealed' : ''} ${className}`}
      style={{ position: 'relative' }}
    >
      {locatorTag && (
        <div style={{
          position: 'absolute',
          top: 16,
          right: 24,
          fontFamily: 'var(--font-mono)',
          fontSize: 10,
          color: isRevealed ? 'var(--terminal-green)' : 'var(--text-dim)',
          transition: 'color 0.6s ease',
          pointerEvents: 'none',
          display: 'flex',
          alignItems: 'center',
          gap: 6
        }}>
          <span style={{ fontSize: 8 }}>{isRevealed ? '●' : '○'}</span>
          <span>{locatorTag}</span>
        </div>
      )}
      {children}
    </section>
  );
};

export default CinematicSection;
