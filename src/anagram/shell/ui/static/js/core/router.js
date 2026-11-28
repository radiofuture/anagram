// Hash routes. A screen is one module in js/screens/ with one export:
//
//   export const screen = {
//     id: 'sources',                      // also the copy namespace
//     path: '/sources/:id?',              // ':x' is a segment, ':x?' is optional
//     nav: { group: 'main', order: 60 },  // omit for a screen with no rail link
//     parent: null,                       // id of the parent screen
//     access: (overview) => true,         // optional; false sends the person home
//     View,                               // ({ params, query }) => html`…`
//   };
import { effect, signal } from './html.js';
import { store } from './store.js';
import { flightOf, land, noteTraverse, transition } from './motion.js';
import { focusTitle } from './a11y.js';

const screens = new Map();
const version = signal(0);

// Old hashes stay valid. An entry applies when its target screen exists and
// no screen has the old id.
export const REDIRECTS = { join: 'welcome', findings: 'library/findings' };

/**
 * The route on the screen: { id, params, query, from, flight }. `from` is the
 * route before this one. `flight` is 'in' or 'back' when a title moves
 * between a row and a detail screen (motion recipe T3).
 */
export const route = signal(null);

const place = signal({ hash: window.location.hash, entry: null, traverse: false });
const positions = new Map(); // history entry -> { y, focusId }
let serial = 0;
let started = false;

export function register(screen) {
  if (!screen?.id || typeof screen.View !== 'function') throw new Error('A screen needs an id and a View.');
  screens.set(screen.id, screen);
  version.value += 1;
}

export function screenOf(id) {
  return screens.get(id) || null;
}

/** The screens with a rail link in one group, in their order. */
export function navItems(group) {
  void version.value;
  return [...screens.values()].filter((s) => s.nav && s.nav.group === group).sort((a, b) => a.nav.order - b.nav.order);
}

function parse(hash) {
  let raw = hash.replace(/^#\/?/, '');
  let anchor = null;
  const hashCut = raw.indexOf('#');
  if (hashCut >= 0) {
    anchor = raw.slice(hashCut + 1) || null;
    raw = raw.slice(0, hashCut);
  }
  const cut = raw.indexOf('?');
  const path = cut < 0 ? raw : raw.slice(0, cut);
  const query = Object.fromEntries(new URLSearchParams(cut < 0 ? '' : raw.slice(cut + 1)));
  if (anchor && !query.section) query.section = anchor;
  const segments = path
    .split('/')
    .filter(Boolean)
    .map((s) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    });
  return { segments, query };
}

function match(segments) {
  let best = null;
  for (const screen of screens.values()) {
    if (!screen.path) continue;
    const pattern = screen.path.split('/').filter(Boolean);
    if (segments.length > pattern.length) continue;
    const params = {};
    let score = 0;
    let ok = true;
    pattern.forEach((part, i) => {
      const seg = segments[i];
      if (part.startsWith(':')) {
        const optional = part.endsWith('?');
        if (seg === undefined) ok = ok && optional;
        else params[part.slice(1, optional ? -1 : undefined)] = seg;
      } else if (part === seg) {
        score += 1;
      } else {
        ok = false;
      }
    });
    if (ok && (!best || score > best.score)) best = { screen, params, score };
  }
  return best;
}

function redirected(segments) {
  const target = segments.length ? REDIRECTS[segments[0]] : null;
  if (!target || screens.has(segments[0])) return segments;
  const to = target.split('/');
  return screens.has(to[0]) ? [...to, ...segments.slice(1)] : segments;
}

function home() {
  return screens.get('home') || screens.get('findings') || null;
}

/** The screen for a hash. While setup is open, each route but `privacy` is `welcome`. */
export function resolve(hash, overview) {
  if (!overview) return null;
  const { segments, query } = parse(hash);
  const segs = redirected(segments);
  let found = segs.length ? match(segs) : null;
  const plain = (screen) => (screen ? { screen, params: {} } : null);
  const setupOpen = !overview.joined || !overview.setup_done;
  if (setupOpen) {
    if (found?.screen.id !== 'privacy') found = plain(screens.get('welcome'));
  } else if (!segs.length || (found && found.screen.id === 'welcome')) {
    found = plain(home());
  } else if (found?.screen.access && !found.screen.access(overview)) {
    found = plain(home());
  }
  if (!found) found = plain(screens.get('notfound'));
  return found ? { id: found.screen.id, params: found.params, query } : null;
}

/** '#/finding/abc' from a screen id and its params. */
export function href(id, params = {}, query = {}) {
  const screen = screens.get(id);
  const parts = [];
  for (const part of (screen?.path || `/${id}`).split('/').filter(Boolean)) {
    if (!part.startsWith(':')) {
      parts.push(part);
      continue;
    }
    const value = params[part.replace(/^:|\?$/g, '')];
    if (value === undefined || value === null) break;
    parts.push(encodeURIComponent(value));
  }
  const q = new URLSearchParams(query).toString();
  return `#/${parts.join('/')}${q ? `?${q}` : ''}`;
}

/** Go to a hash. `source` is the element of a shared-element move (recipe T3). */
export function navigate(hash, { replace = false, source = null } = {}) {
  void source;
  if (window.location.hash === hash) return;
  if (replace) window.location.replace(hash);
  else window.location.hash = hash;
}

/** True when the screen `id` is the route on the screen, or a parent of it. */
export function isCurrent(id) {
  let at = route.value ? screens.get(route.value.id) : null;
  for (let n = 0; at && n < 8; n += 1) {
    if (at.id === id) return true;
    at = at.parent ? screens.get(at.parent) : null;
  }
  return false;
}

function entryId() {
  const state = window.history.state;
  return state && typeof state.ag === 'string' ? state.ag : null;
}

function newEntry() {
  serial += 1;
  const id = `${Date.now().toString(36)}-${serial}`;
  window.history.replaceState({ ...(window.history.state || {}), ag: id }, '');
  return id;
}

function remember() {
  const at = place.peek().entry;
  if (!at) return;
  const active = document.activeElement;
  positions.set(at, { y: window.scrollY, focusId: active?.id ? active.id : null });
}

function onHashChange() {
  remember();
  const known = entryId();
  if (known !== null) noteTraverse(place.peek().hash, window.location.hash);
  place.value = { hash: window.location.hash, entry: known || newEntry(), traverse: known !== null };
}

function settle(first, back) {
  if (first) return;
  const saved = back ? positions.get(place.peek().entry) : null;
  if (!saved) {
    // Forward: the top of the new screen, focus on its title.
    window.scrollTo(0, 0);
    focusTitle();
    land();
    return;
  }
  // Back: the scroll position and the focus of before. The screen can be
  // shorter until its data is ready, so wait for that (at most 2 s).
  const end = performance.now() + 2000;
  const restore = () => {
    const main = document.getElementById('main');
    const waiting = main && main.dataset.state === 'loading';
    const short = document.documentElement.scrollHeight - window.innerHeight < saved.y;
    if ((waiting || short) && performance.now() < end) {
      requestAnimationFrame(restore);
      return;
    }
    window.scrollTo(0, saved.y);
    const el = saved.focusId ? document.getElementById(saved.focusId) : null;
    if (el) el.focus({ preventScroll: true });
    else focusTitle();
    land();
  };
  restore();
}

/** Start the router: read the hash now and on each change. */
export function start() {
  if (started) return;
  started = true;
  if ('scrollRestoration' in window.history) window.history.scrollRestoration = 'manual';
  place.value = { hash: window.location.hash, entry: entryId() || newEntry(), traverse: false };
  window.addEventListener('hashchange', onHashChange);
  let timer = null;
  window.addEventListener(
    'scroll',
    () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        const at = place.peek().entry;
        if (at) positions.set(at, { ...(positions.get(at) || { focusId: null }), y: window.scrollY });
      }, 100);
    },
    { passive: true },
  );

  let settled = null;
  effect(() => {
    void version.value;
    const at = place.value;
    const next = resolve(at.hash, store.overview.value);
    if (!next) return;
    const before = route.peek();
    if (
      before &&
      before.id === next.id &&
      JSON.stringify([before.params, before.query]) === JSON.stringify([next.params, next.query])
    )
      return;
    const from = before ? { id: before.id, params: before.params, query: before.query } : null;
    const flight = before ? flightOf(at.hash) : null;
    transition(
      () => {
        route.value = { ...next, from, flight };
      },
      { kind: before ? 'screen' : 'none' },
    ).then(() => {
      // Back restores only when the person moved in the history. A route
      // that changes for another reason (setup ends) starts at its top.
      const back = at.traverse && at !== settled;
      settled = at;
      settle(before === null, back);
    });
  });
}
