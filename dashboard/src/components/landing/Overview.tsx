import { useRef } from 'react';
import type { AegisApi } from '../../lib/useAegisApi';
import { useReveals } from '../../lib/motion';
import RuleLab from '../RuleLab';
import Story from '../story/Story';
import About from './About';
import Closing from './Closing';
import Glossary from './Glossary';
import Hero from './Hero';
import LiveEvent from './LiveEvent';
import Rules from './Rules';
import Scope from './Scope';
import Stack from './Stack';

export default function Overview({ api }: { api: AegisApi }) {
  const root = useRef<HTMLElement>(null);
  useReveals(root);

  return (
    <main id="overview" className="overview" ref={root} tabIndex={-1}>
      <Hero />
      <About />
      <Story events={api.events.data} />
      <Rules />
      <RuleLab />
      <LiveEvent events={api.events} onRetry={api.refresh} onSimulated={api.refresh} />
      <Glossary />
      <Stack />
      <Scope />
      <Closing />
    </main>
  );
}
