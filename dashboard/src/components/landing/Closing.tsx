import Icon from '../Icon';
import Mark from '../Mark';
import Split from './Split';

const REPOSITORY = 'https://github.com/RR-1902/aegis';

export default function Closing() {
  return (
    <section className="closing" aria-labelledby="closing-title">
      <div className="closing__light" aria-hidden="true" />
      <div className="closing__mark" data-reveal="">
        <Mark size={64} />
      </div>
      <Split as="h2" id="closing-title" className="closing__title" text="See the evidence for yourself." />
      <p className="closing__lead" data-reveal="">
        Open the console to inspect every stored event, or read the source and run the tests.
      </p>
      <div className="closing__actions" data-reveal="">
        <a className="button button--primary button--large" href="#/ledger">
          <Icon name="ledger" size={18} />
          Open the live console
        </a>
        <a className="button button--large" href={REPOSITORY} target="_blank" rel="noreferrer">
          <Icon name="code" size={18} />
          View the source
          <Icon name="external" size={16} />
        </a>
      </div>
    </section>
  );
}
