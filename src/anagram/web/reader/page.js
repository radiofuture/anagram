// The full page of the reading view in the member app: /reader/#<grant_id>.
// It opens the received finding (`POST /api/shared/<grant_id>/open`) and
// shows it with `mountReader`.

import { el } from './dom.js';
import { mountReader } from './reader.js';
import { WORDS, say } from './words.js';

const GRANT = /^[0-9a-f]{32}$/;
const root = document.getElementById('reader');
const status = (key) =>
  root.replaceChildren(el('p', { class: 'rd-note rd-page-note', role: 'status' }, say(WORDS, key)));
let view = null;

async function open() {
  view?.destroy();
  view = null;
  const grant = decodeURIComponent(location.hash.slice(1));
  if (!GRANT.test(grant)) {
    status('no_finding');
    return;
  }
  status('opening');
  let model;
  try {
    const response = await fetch(`/api/shared/${grant}/open`, { method: 'POST', credentials: 'same-origin' });
    if (!response.ok) throw new Error(String(response.status));
    model = await response.json();
  } catch {
    status('open_failed');
    return;
  }
  const base = `/api/shared/${grant}`;
  view = mountReader(root, model, {
    file: (item) => `${base}/files/${item.slot}`,
    figure: (item, figure) => `${base}/figures/${item.slot}/${encodeURIComponent(figure.id)}`,
  });
  document.title = `${model.title || say(WORDS, 'back')} · Anagram`;
}

window.addEventListener('hashchange', open);
open();
