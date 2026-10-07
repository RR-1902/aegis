import { useLayoutEffect, useRef } from 'react';
import { gsap, prefersReducedMotion, usePauseOffscreen } from '../../lib/motion';
import Icon from '../Icon';
import AegisLens from './AegisLens';
import PacketStream from './PacketStream';
import SectionLink from './SectionLink';

export default function Hero() {
  const root = useRef<HTMLElement>(null);
  const cue = usePauseOffscreen<HTMLAnchorElement>();

  // One orchestrated entrance: kicker, headline lines, lead, actions, then the instrument.
  useLayoutEffect(() => {
    if (!root.current || prefersReducedMotion()) return undefined;
    const context = gsap.context(() => {
      const timeline = gsap.timeline({ defaults: { ease: 'expo.out' } });
      timeline
        .from('.hero__kicker', { opacity: 0, y: 16, duration: 0.9 })
        .fromTo(
          '.hero__line-inner',
          { yPercent: 110, y: 0 },
          { yPercent: 0, y: 0, duration: 1.2, stagger: 0.12, clearProps: 'transform' },
          '-=0.6',
        )
        .from('.hero__lead', { opacity: 0, y: 20, duration: 1 }, '-=0.8')
        .from('.hero__actions > *', { opacity: 0, y: 16, duration: 0.9, stagger: 0.08 }, '-=0.75')
        .from('.hero__facts > *', { opacity: 0, y: 12, duration: 0.8, stagger: 0.06 }, '-=0.7')
        .from('.lens', { opacity: 0, scale: 0.9, duration: 1.6 }, 0.25)
        .from('.stream', { opacity: 0, duration: 1.4 }, 0.6)
        .from('.hero__cue', { opacity: 0, y: -8, duration: 0.8 }, 1.2);
    }, root);
    return () => context.revert();
  }, []);

  return (
    <section className="hero" ref={root} aria-labelledby="hero-title">
      <div className="hero__light" aria-hidden="true" />
      <div className="hero__grid" aria-hidden="true" />
      <div className="hero__inner">
        <div className="hero__copy">
          <p className="hero__kicker">
            <Icon name="shield" size={16} />
            Explainable network intrusion detection and response
          </p>
          <h1 id="hero-title" className="hero__title">
            <span className="hero__line">
              <span className="hero__line-inner">Detect the attack.</span>
            </span>
            <span className="hero__line hero__line--soft">
              <span className="hero__line-inner">Explain the verdict.</span>
            </span>
          </h1>
          <p className="hero__lead">
            AEGIS watches live network traffic, catches SYN floods and port scans with transparent rules,
            and records the evidence, risk score, policy decision and response behind every alert.
          </p>
          <div className="hero__actions">
            <SectionLink className="button button--primary button--large" href="#story">
              Follow an attack through AEGIS
              <Icon name="arrow" size={18} />
            </SectionLink>
            <a className="button button--large" href="#/ledger">
              <Icon name="ledger" size={18} />
              Open the live console
            </a>
            <SectionLink className="hero__simulate" href="#simulate">
              <Icon name="flood" size={18} />
              Simulate an attack
            </SectionLink>
          </div>
          <dl className="hero__facts">
            <div>
              <dt>Detection</dt>
              <dd>Rule based, no black box</dd>
            </div>
            <div>
              <dt>Response</dt>
              <dd>Simulated, never executed</dd>
            </div>
            <div>
              <dt>Record</dt>
              <dd>Every alert, with its evidence</dd>
            </div>
          </dl>
        </div>
        <AegisLens />
      </div>
      <PacketStream />
      <SectionLink className="hero__cue" href="#about" ref={cue}>
        <span>What is AEGIS?</span>
        <span className="hero__cue-line" aria-hidden="true" />
      </SectionLink>
    </section>
  );
}
