import { getApiBaseUrl } from '../api/client';
import Icon from './Icon';
import Mark from './Mark';

const REPOSITORY = 'https://github.com/RR-1902/aegis';

export default function Footer({ version }: { version: string | null }) {
  const apiBase = getApiBaseUrl().replace(/\/$/, '');
  return (
    <footer className="footer">
      <div className="footer__brand">
        <Mark size={26} />
        <div>
          <p className="wordmark">AEGIS</p>
          <p className="muted">Explainable network intrusion detection and response</p>
        </div>
      </div>
      <ul className="footer__links">
        <li>
          <a className="footer__link" href="#/ledger">
            <Icon name="ledger" size={16} />
            Console
          </a>
        </li>
        <li>
          <a className="footer__link" href={REPOSITORY} target="_blank" rel="noreferrer">
            <Icon name="code" size={16} />
            Source code
          </a>
        </li>
        <li>
          <a className="footer__link" href={`${apiBase}/docs`} target="_blank" rel="noreferrer">
            <Icon name="external" size={16} />
            API reference
          </a>
        </li>
      </ul>
      <p className="footer__meta muted">
        {version ? `API version ${version}` : 'API version unknown'}
        <span aria-hidden="true">/</span>
        <code translate="no">{apiBase.replace(/^https?:\/\//, '')}</code>
      </p>
    </footer>
  );
}
