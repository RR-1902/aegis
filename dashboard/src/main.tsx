import React from 'react';
import ReactDOM from 'react-dom/client';
import '@fontsource-variable/hubot-sans/standard.css';
import '@fontsource-variable/mona-sans/standard.css';
import '@fontsource-variable/geist-mono';
import 'lenis/dist/lenis.css';
import App from './App';
import './styles/site.css';
import './styles/story.css';
import './styles/console.css';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
