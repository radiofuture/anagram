// The words of the product. They live in static/copy/<id>.json, one file for
// each screen or component group. `t('sources.items', { n: 12 })` gives
// '12 items'. A key that does not exist shows as the key and is reported, so
// that a missing text cannot ship as an empty place.
import { signal } from './html.js';

const words = signal({});
const reported = new Set();

/** Add copy: `{ <file stem>: { <key>: text | { one, other } } }`. */
export function setCopy(more) {
  words.value = { ...words.value, ...more };
}

function find(key) {
  let node = words.value;
  for (const part of key.split('.')) {
    if (node === null || typeof node !== 'object') return undefined;
    node = node[part];
  }
  return node;
}

export function has(key) {
  return find(key) !== undefined;
}

export function t(key, params = {}) {
  let text = find(key);
  if (text !== null && typeof text === 'object') text = text[params.n === 1 ? 'one' : 'other'];
  if (typeof text !== 'string') {
    if (!reported.has(key)) {
      reported.add(key);
      console.error(`copy: no text for the key ${key}`);
    }
    return key;
  }
  return text.replace(/\{(\w+)\}/g, (all, name) => (name in params ? String(params[name]) : all));
}

/**
 * A text with a part that is not text (a link, a code word):
 * `tx('library.drafts_empty', { link })`. Gives strings and nodes for a template.
 */
export function tx(key, nodes = {}) {
  return t(key)
    .split(/(\{\w+\})/)
    .filter(Boolean)
    .map((part) => {
      const name = part.startsWith('{') ? part.slice(1, -1) : null;
      return name !== null && name in nodes ? nodes[name] : part;
    });
}
