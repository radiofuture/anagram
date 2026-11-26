// The only global state. Server data lives in resources (resource.js). Form
// input lives in its component.
import { signal } from './html.js';

export const store = {
  overview: signal(null), // GET /api/overview
  conn: signal('connecting'), // 'connecting' | 'live' | 'retrying' | 'down'
  notice: signal(null), // what the rail foot shows: null | 'retrying' | 'down'
  serverId: signal(null), // from the hello event
  launch: signal(false), // the server refused the cookie
  fault: signal(null), // the product cannot start: the message, or { keychain: true }
  arrived: signal(false), // the setup ended in this page: Home sets down its first panel one time
  live: {
    join: signal(null), // last join.state
    sources: signal({}), // { [sourceId]: progress } from source.progress
    jobs: signal({}), // { [jobId]: job } from job.progress
    fresh: signal(new Set()), // keys that arrived after the first paint; drives the "new" edge
  },
  dialog: signal(null), // { View, props, resolve, opener } for the one sheet
};

/** Mark a key as new (it arrived after the first paint of its list). */
export function markFresh(key) {
  if (store.live.fresh.value.has(key)) return;
  store.live.fresh.value = new Set([...store.live.fresh.value, key]);
}

export function clearFresh(key) {
  if (!store.live.fresh.value.has(key)) return;
  const next = new Set(store.live.fresh.value);
  next.delete(key);
  store.live.fresh.value = next;
}
