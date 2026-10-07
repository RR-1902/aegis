import type { CSSProperties } from 'react';
import Mark from '../Mark';
import { usePauseOffscreen } from '../../lib/motion';

const TICKS = Array.from({ length: 120 }, (_, index) => index);

/** Contacts the sweep lights up as it passes. Angles in degrees, clockwise from the top. */
const CONTACTS = [
  { angle: 38, radius: 0.62, level: 'critical', label: 'SYN flood' },
  { angle: 132, radius: 0.78, level: 'high', label: 'Port scan' },
  { angle: 214, radius: 0.48, level: 'low', label: 'DNS' },
  { angle: 296, radius: 0.7, level: 'medium', label: 'Probe' },
];

const SWEEP_SECONDS = 8;

/**
 * The hero instrument: a slowly turning range ring, a sonar-style sweep and a few contacts
 * that light as the sweep crosses them. Each moving layer is its own element and only its
 * transform or opacity animates; everything pauses off screen.
 */
export default function AegisLens() {
  const ref = usePauseOffscreen<HTMLDivElement>();
  return (
    <div className="lens" ref={ref} aria-hidden="true">
      <div className="lens__halo" />
      <div className="lens__layer lens__ring lens__ring--ticks">
        <svg viewBox="0 0 400 400">
          {TICKS.map((tick) => (
            <line
              key={tick}
              x1="200"
              y1={tick % 10 === 0 ? 6 : 12}
              x2="200"
              y2="20"
              transform={`rotate(${tick * 3} 200 200)`}
              className={tick % 10 === 0 ? 'lens__tick lens__tick--major' : 'lens__tick'}
            />
          ))}
        </svg>
      </div>
      <div className="lens__layer lens__ring lens__ring--dash">
        <svg viewBox="0 0 400 400">
          <circle cx="200" cy="200" r="150" className="lens__dash" />
        </svg>
      </div>
      <div className="lens__layer">
        <svg viewBox="0 0 400 400">
          <circle cx="200" cy="200" r="182" className="lens__circle" />
          <circle cx="200" cy="200" r="118" className="lens__circle lens__circle--faint" />
          <circle cx="200" cy="200" r="78" className="lens__circle lens__circle--faint" />
          <path d="M200 30v340M30 200h340" className="lens__cross" />
        </svg>
      </div>
      <div className="lens__layer lens__sweep" style={{ '--sweep': `${SWEEP_SECONDS}s` } as CSSProperties} />
      {CONTACTS.map((contact) => {
        const radians = ((contact.angle - 90) * Math.PI) / 180;
        const x = 50 + Math.cos(radians) * contact.radius * 45.5;
        const y = 50 + Math.sin(radians) * contact.radius * 45.5;
        return (
          <span
            key={contact.label}
            className="lens__contact"
            data-level={contact.level}
            style={
              {
                left: `${x}%`,
                top: `${y}%`,
                '--delay': `${(contact.angle / 360) * SWEEP_SECONDS - SWEEP_SECONDS}s`,
                '--sweep': `${SWEEP_SECONDS}s`,
              } as CSSProperties
            }
          >
            <span className="lens__contact-ring" />
            <span className="lens__contact-label">{contact.label}</span>
          </span>
        );
      })}
      <div className="lens__core">
        <Mark size={96} />
      </div>
      <p className="lens__readout lens__readout--a">
        <span>Window</span>5 s
      </p>
      <p className="lens__readout lens__readout--b">
        <span>Rules</span>2
      </p>
      <p className="lens__readout lens__readout--c">
        <span>Mode</span>Safe
      </p>
    </div>
  );
}
