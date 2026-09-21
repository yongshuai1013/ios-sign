import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
// `src/pairing/remote-pairing.ts` uses the Node `Buffer` global for base64
// helpers; polyfill it for the browser.
import { Buffer } from 'buffer';
import './style.css';
import { App } from './App';

if (typeof (globalThis as Record<string, unknown>)['Buffer'] === 'undefined') {
  (globalThis as Record<string, unknown>)['Buffer'] = Buffer;
}

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error('App root is missing');
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
