// Server data. A resource is one cached GET. A component that reads
// `.data.value` updates when the data changes. A live event marks the
// resource stale and starts a reload; the old data stays on the screen during
// the reload (a loading state must not erase a result).
import { signal, useEffect, useRef, useState } from './html.js';
import { api } from './api.js';
import { on } from './events.js';

const cache = new Map();

/**
 * One cached GET.
 * @param {string} path the API path, with its query
 * @param {{topics?: string[], throttle?: number, data?: object}} [opts]
 *   topics: event types ('draft.changed') or topics ('source') that make the
 *   resource stale. throttle: at most one reload from events in this many ms.
 * @returns {{state, data, error, load, reload, patch}}
 */
export function resource(path, { topics = [], throttle = 0, data = null } = {}) {
  let r = cache.get(path);
  if (r) {
    for (const topic of topics) r.topics.add(topic);
    if (throttle) r.throttle = throttle;
    return r;
  }
  let running = null;
  let again = false;
  let timer = null;
  let last = 0;

  async function fetchNow() {
    r.state.value = r.data.peek() === null ? 'loading' : 'stale';
    try {
      const value = await api('GET', path);
      r.data.value = value;
      r.error.value = null;
      r.state.value = 'ready';
    } catch (err) {
      r.error.value = err;
      r.state.value = 'error';
    }
    last = Date.now();
  }

  r = {
    path,
    topics: new Set(topics),
    throttle,
    users: 0,
    state: signal('idle'), // 'idle' | 'loading' | 'ready' | 'stale' | 'error'
    data: data || signal(null),
    error: signal(null),
    /** Load if there is no data yet. */
    load() {
      return r.data.peek() === null || r.state.peek() === 'idle' ? r.reload() : Promise.resolve();
    },
    /** Get the data again. Never rejects: an error goes into `error`. */
    reload() {
      if (running) {
        again = true;
        return running;
      }
      running = (async () => {
        do {
          again = false;
          await fetchNow();
        } while (again);
        running = null;
      })();
      return running;
    },
    /** Apply small event data at once, before the reload ends. */
    patch(fn) {
      if (r.data.peek() !== null) r.data.value = fn(r.data.peek());
    },
    /** An event made the data old. */
    stale() {
      if (!r.users) {
        if (r.state.peek() !== 'loading') r.state.value = 'idle';
        return;
      }
      const wait = r.throttle - (Date.now() - last);
      if (wait <= 0) {
        r.reload();
      } else if (!timer) {
        timer = setTimeout(() => {
          timer = null;
          if (r.users) r.reload();
          else r.state.value = 'idle';
        }, wait);
      }
    },
  };
  cache.set(path, r);
  return r;
}

on('*', (event) => {
  const all = event.type === 'resync';
  const paths = event.type === 'resource.stale' && Array.isArray(event.data.paths) ? event.data.paths : [];
  for (const r of cache.values()) {
    if (all || paths.includes(r.path) || r.topics.has(event.type) || r.topics.has(event.topic)) r.stale();
  }
});

// With no live stream, a resource in use loads again when the window gets focus.
let streamLive = () => true;
export function setStreamCheck(fn) {
  streamLive = fn;
}
window.addEventListener('focus', () => {
  if (streamLive()) return;
  for (const r of cache.values()) r.stale();
});

const NONE = { state: signal('idle'), data: signal(null), error: signal(null), load() {}, reload() {}, patch() {} };

/** Hook: use a resource while the component is on the screen. `path` can be null. */
export function useResource(path, opts) {
  const r = path ? resource(path, opts) : NONE;
  useEffect(() => {
    if (!path) return undefined;
    r.users += 1;
    // Old data shows at once; a reload brings the new data. A load that
    // runs now is new enough.
    if (!['loading', 'stale'].includes(r.state.peek())) r.reload();
    return () => {
      r.users -= 1;
    };
  }, [path]);
  return r;
}

/**
 * True when the route of a resource is not on this server (404): a route of
 * another track that is not built yet. The screen then shows its empty
 * state, not an error.
 */
export function absent(r) {
  return Boolean(r.error.value && r.error.value.status === 404);
}

/** The data of a resource that can be absent: null while it loads, after an error, or when its route is not there. */
export function optional(r) {
  return r.error.value && r.data.value === null ? null : r.data.value;
}

/** Reload the cached resources of these paths. */
export function invalidate(paths) {
  return Promise.all(
    paths.map((p) => {
      const r = cache.get(p);
      if (!r) return null;
      if (r.users) return r.reload();
      r.state.value = 'idle';
      return null;
    }),
  );
}

/** An action: call the API, then reload the resources that it changed. */
export async function mutate(method, path, body, { invalidate: paths = [] } = {}) {
  const out = await api(method, path, body);
  await invalidate(paths);
  return out;
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Hook: the local draft of a form. It copies the server value on mount and
 * after a save. If the server value changes while the person has other
 * input, `outdated` is true and the input stays.
 */
export function useDraft(source) {
  const [draft, setDraft] = useState(source);
  const [outdated, setOutdated] = useState(false);
  const base = useRef(source);
  useEffect(() => {
    if (same(source, base.current)) return;
    if (same(draft, base.current) || same(draft, source)) {
      base.current = source;
      setDraft(source);
      setOutdated(false);
    } else {
      setOutdated(true);
    }
  }, [JSON.stringify(source)]);
  return {
    value: draft,
    set: setDraft,
    dirty: !same(draft, base.current),
    outdated,
    reset() {
      base.current = source;
      setDraft(source);
      setOutdated(false);
    },
  };
}
