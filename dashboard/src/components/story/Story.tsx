import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import type { SecurityEvent } from '../../types/api';
import { gsap, ScrollTrigger, prefersReducedMotion, scrollToTarget, usePauseOffscreen } from '../../lib/motion';
import { ledgerHref } from '../../lib/route';
import Icon, { type IconName } from '../Icon';
import Term from '../Term';
import SectionHead from '../landing/SectionHead';
import { ATTACK } from './attack';
import {
  CaptureScene,
  DecideScene,
  DetectScene,
  FeatureScene,
  FlowScene,
  ParseScene,
  RecordScene,
  RespondScene,
  ScoreScene,
  WindowScene,
} from './Scenes';

type Step = {
  id: string;
  icon: IconName;
  title: string;
  module: string;
  body: ReactNode;
};

const STEPS: Step[] = [
  {
    id: 'capture',
    icon: 'capture',
    title: 'Capture',
    module: 'app/capture/packet_capture.py',
    body: (
      <>
        An attacker at <span className="mono">{ATTACK.source}</span> sends 24 <Term id="syn">SYN</Term> packets to
        24 different ports on a server, all inside 0.8 seconds. AEGIS listens on the network interface through
        Scapy, and a <Term id="bpf">BPF filter</Term> lets only TCP and UDP through.
      </>
    ),
  },
  {
    id: 'parse',
    icon: 'layers',
    title: 'Parse',
    module: 'app/protocols/parser.py',
    body: (
      <>
        Each <Term id="packet">packet</Term> is unpacked layer by layer. AEGIS reads the{' '}
        <Term id="header">headers</Term> only: hardware and IP addresses, ports, TCP flags, size and capture
        time. The payload is never read.
      </>
    ),
  },
  {
    id: 'flow',
    icon: 'flow',
    title: 'Group into flows',
    module: 'app/flows/flow_key.py',
    body: (
      <>
        Packets that share a key form a <Term id="flow">flow</Term>. Keyed by{' '}
        <Term id="three-tuple">three-tuple</Term>, all 24 probes become one flow. The default{' '}
        <Term id="five-tuple">five-tuple</Term> would split them into 24 flows of one packet, and the scan
        would pass unseen.
      </>
    ),
  },
  {
    id: 'window',
    icon: 'window',
    title: 'Cut into windows',
    module: 'app/flows/time_window.py',
    body: (
      <>
        Flows are measured in five-second <Term id="window">time windows</Term> aligned to the clock. The whole
        burst lands in one window. Once that window closes, it is summarised exactly once, so nothing is counted
        twice.
      </>
    ),
  },
  {
    id: 'features',
    icon: 'features',
    title: 'Measure',
    module: 'app/features/extractor.py',
    body: (
      <>
        The window becomes 28 <Term id="feature">features</Term>. Three decide this case: 30 SYN packets per
        second, every connection left incomplete, and 24 unique destination ports.
      </>
    ),
  },
  {
    id: 'detect',
    icon: 'detect',
    title: 'Detect',
    module: 'app/detection/rules/',
    body: (
      <>
        Two <Term id="rule">detection rules</Term> compare those features with fixed{' '}
        <Term id="threshold">thresholds</Term>. Both fire, and both clear their thresholds, so each has high{' '}
        <Term id="severity">severity</Term>. The comparisons are kept as <Term id="evidence">evidence</Term>.
      </>
    ),
  },
  {
    id: 'score',
    icon: 'score',
    title: 'Score',
    module: 'app/scoring/risk_scorer.py',
    body: (
      <>
        Each rule adds fixed points: 40 for a high port scan and 55 for a high SYN flood. The{' '}
        <Term id="risk-score">risk score</Term> is 95 out of 100, a critical <Term id="risk-level">risk level</Term>.
        It is a transparent sum, not a probability.
      </>
    ),
  },
  {
    id: 'decide',
    icon: 'policy',
    title: 'Decide',
    module: 'app/policy/engine.py',
    body: (
      <>
        Critical risk with a SYN flood could justify blocking the source. The <Term id="policy">policy</Term>{' '}
        engine refuses unless the evidence names an <Term id="observed-source">observed source</Term>. It does
        not, so AEGIS raises an alert instead of guessing who to block.
      </>
    ),
  },
  {
    id: 'respond',
    icon: 'respond',
    title: 'Respond',
    module: 'app/response/engine.py',
    body: (
      <>
        The response engine validates the decision step by step. An alert needs no action, so none is taken.
        Even a block would only be <Term id="simulated">simulated</Term> while{' '}
        <Term id="safe-mode">SAFE_MODE</Term> is on. AEGIS never runs a firewall command.
      </>
    ),
  },
  {
    id: 'record',
    icon: 'record',
    title: 'Record',
    module: 'app/storage/security_event_store.py',
    body: (
      <>
        Everything above is sealed into one immutable <Term id="security-event">security event</Term>. Its{' '}
        <Term id="sha-256">SHA-256 ID</Term> comes from the flow key and window, so the same traffic always gives
        the same ID. The event joins the <Term id="ledger">ledger</Term>, served by the{' '}
        <Term id="rest-api">REST API</Term>.
      </>
    ),
  },
];

function findStoryEvent(events: SecurityEvent[] | null): SecurityEvent | null {
  return (
    events?.find(
      (event) =>
        event.flow_key.src_ip === ATTACK.source &&
        event.flow_key.dst_ip === ATTACK.target &&
        event.detections.length === 2 &&
        event.risk.score === 95,
    ) ?? null
  );
}

function renderScene(index: number, active: boolean, eventId: string | null) {
  switch (STEPS[index].id) {
    case 'capture':
      return <CaptureScene active={active} />;
    case 'parse':
      return <ParseScene active={active} />;
    case 'flow':
      return <FlowScene active={active} />;
    case 'window':
      return <WindowScene active={active} />;
    case 'features':
      return <FeatureScene active={active} />;
    case 'detect':
      return <DetectScene active={active} />;
    case 'score':
      return <ScoreScene active={active} />;
    case 'decide':
      return <DecideScene active={active} />;
    case 'respond':
      return <RespondScene active={active} />;
    default:
      return <RecordScene active={active} eventId={eventId} />;
  }
}

function StepText({ index, eventId }: { index: number; eventId: string | null }) {
  const step = STEPS[index];
  return (
    <div className="story-step" key={step.id}>
      <p className="story-step__count">
        <span className="story-step__icon">
          <Icon name={step.icon} size={20} />
        </span>
        Stage {index + 1} of {STEPS.length}
      </p>
      <h3 className="story-step__title">{step.title}</h3>
      <p className="story-step__body">{step.body}</p>
      <code className="story-step__module">{step.module}</code>
      {step.id === 'record' && eventId && (
        <a className="button story-step__cta" href={ledgerHref({ event: eventId })}>
          <Icon name="ledger" size={18} />
          Inspect this event in the console
        </a>
      )}
    </div>
  );
}

/**
 * "Follow one attack": on wide screens the section pins and scrolling walks through the ten
 * stages; on narrow screens, or with reduced motion, the stages stack and play as they appear.
 */
const PIN_QUERY = '(min-width: 1024px) and (min-height: 640px) and (prefers-reduced-motion: no-preference)';

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => typeof window !== 'undefined' && window.matchMedia(query).matches);
  useEffect(() => {
    const list = window.matchMedia(query);
    const onChange = () => setMatches(list.matches);
    list.addEventListener('change', onChange);
    return () => list.removeEventListener('change', onChange);
  }, [query]);
  return matches;
}

export default function Story({ events }: { events: SecurityEvent[] | null }) {
  const [active, setActive] = useState(0);
  const pinned = useMediaQuery(PIN_QUERY);
  const pinRef = useRef<HTMLDivElement>(null);
  const sectionRef = usePauseOffscreen<HTMLElement>();
  const triggerRef = useRef<ScrollTrigger | null>(null);
  const storyEvent = findStoryEvent(events);
  const eventId = storyEvent?.event_id ?? null;

  useLayoutEffect(() => {
    const pin = pinRef.current;
    if (!pinned || !pin) return undefined;
    const context = gsap.context(() => {
      triggerRef.current = ScrollTrigger.create({
        trigger: pin,
        start: 'top top',
        end: () => `+=${window.innerHeight * 0.85 * STEPS.length}`,
        pin: true,
        anticipatePin: 1,
        invalidateOnRefresh: true,
        onUpdate: (self) => {
          // Write each segment's transform directly. A custom property on the pin would be
          // inherited by every element in all ten scenes and restyle them on every frame.
          const fills = pin.querySelectorAll<HTMLElement>('.story__dot-fill');
          fills.forEach((fill, index) => {
            const amount = Math.min(1, Math.max(0, self.progress * STEPS.length - index));
            const value = `scaleX(${amount.toFixed(3)})`;
            if (fill.style.transform !== value) fill.style.transform = value;
          });
          const next = Math.min(STEPS.length - 1, Math.floor(self.progress * STEPS.length));
          setActive((current) => (current === next ? current : next));
        },
      });
    }, pin);
    ScrollTrigger.refresh();
    return () => {
      triggerRef.current = null;
      context.revert();
      setActive(0);
    };
  }, [pinned]);

  const jumpTo = (index: number) => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const position = trigger.start + ((index + 0.5) / STEPS.length) * (trigger.end - trigger.start);
    scrollToTarget(position);
  };

  return (
    <section className="story" id="story" aria-labelledby="story-title" ref={sectionRef}>
      <div className="story__intro">
        <SectionHead id="story-title" label="How it works" icon="flow" title="Follow one attack through AEGIS">
          <p>
            A fast port scan meets ten small modules, each with one job. On the left is what AEGIS does; on the
            right is what it sees. The numbers are the real ones for this attack, and the event it produced is in
            the ledger.
          </p>
        </SectionHead>
      </div>

      <div className={pinned ? 'story__pin is-pinned' : 'story__pin'} ref={pinRef}>
        {pinned ? (
          <div className="story__frame">
            <div className="story__left">
              <ol className="story__progress" aria-label="Stages">
                {STEPS.map((step, index) => (
                  <li key={step.id}>
                    <button
                      type="button"
                      className="story__dot"
                      aria-current={index === active ? 'step' : undefined}
                      onClick={() => jumpTo(index)}
                    >
                      <span className="story__dot-fill" />
                      <span className="visually-hidden">
                        Stage {index + 1}: {step.title}
                      </span>
                    </button>
                    <span className="story__dot-label" aria-hidden="true">
                      {step.title}
                    </span>
                  </li>
                ))}
              </ol>
              <StepText index={active} eventId={eventId} />
            </div>
            <div className="story__stage">
              <p className="story__stage-label">
                <span className="story__stage-pulse" aria-hidden="true" />
                What AEGIS sees
              </p>
              {STEPS.map((step, index) => (
                <div className="story__scene-slot" key={step.id}>
                  {renderScene(index, index === active, eventId)}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <ol className="story__list">
            {STEPS.map((step, index) => (
              <StackedStep key={step.id} index={index} eventId={eventId} />
            ))}
          </ol>
        )}
      </div>
    </section>
  );
}

function StackedStep({ index, eventId }: { index: number; eventId: string | null }) {
  const ref = useRef<HTMLLIElement>(null);
  const [visible, setVisible] = useState(prefersReducedMotion());
  useEffect(() => {
    const element = ref.current;
    if (!element || visible) return undefined;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.35 },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [visible]);

  return (
    <li className="story__item" ref={ref}>
      <StepText index={index} eventId={eventId} />
      <div className="story__stage story__stage--inline">{renderScene(index, visible, eventId)}</div>
    </li>
  );
}
