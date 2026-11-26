// Motion on the brand timings (--rf-ui-press-time, --rf-ui-change-time,
// --rf-ui-number-time, --rf-ui-ease). Each motion has a cause: an input of
// the person or one real event. Nothing loops. With reduced motion, each
// change is immediate.
import { signal } from './html.js';

const running = new WeakMap(); // element -> the height or fade motion that runs now

const query = window.matchMedia('(prefers-reduced-motion: reduce)');
export const reduced = signal(query.matches);
query.addEventListener('change', () => {
  reduced.value = query.matches;
  // Finish the motion that runs now (MOTION.md, rolling numbers).
  if (query.matches) for (const a of document.getAnimations()) a.finish();
});

/** A brand timing in ms: 'press', 'change', or 'number'. 0 with reduced motion. */
export function timing(name = 'change') {
  if (reduced.value) return 0;
  const raw = getComputedStyle(document.body).getPropertyValue(`--rf-ui-${name}-time`).trim();
  const ms = raw.endsWith('ms') ? parseFloat(raw) : parseFloat(raw) * 1000;
  return Number.isFinite(ms) ? ms : 0;
}

export function ease() {
  return getComputedStyle(document.body).getPropertyValue('--rf-ui-ease').trim() || 'ease-out';
}

// ------------------------------------------------- T3, row to detail and back
//
// The title of the chosen row moves to the place of the screen title. Back
// runs it in reverse: the screen title moves into its row. Only transform
// moves (a translate and a scale from the top left), and only when the
// row and the screen title have the same words. Each flight is one
// time, on a click or on Back, and is gone after 2 s if no screen uses it.

let flight = null; // { dir: 'in'|'back', hash, row, from: {left, top, size, text}, at }
const rowWords = new Map(); // detail hash -> the words of the row that opened it

function box(el) {
  const r = el.getBoundingClientRect();
  return {
    left: r.left,
    top: r.top,
    size: parseFloat(getComputedStyle(el).fontSize) || 16,
    text: (el.textContent || '').replace(/\s+/g, ' ').trim(),
  };
}

const plainClick = (e) => e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey;

document.addEventListener(
  'click',
  (e) => {
    if (!plainClick(e) || !e.target?.closest) return;
    // The back link of a detail screen: the title goes back into its row.
    const back = e.target.closest('#main .ag-back a');
    if (back) {
      noteTraverse(window.location.hash, back.getAttribute('href') || '');
      return;
    }
    const link = e.target.closest('#main a.ag-row-link');
    if (!link) return;
    const title = link.querySelector('.ag-row-title');
    const hash = link.getAttribute('href') || '';
    if (!title || !hash.startsWith('#/')) return;
    flight = { dir: 'in', hash, row: hash, from: box(title), at: performance.now() };
    rowWords.set(hash, flight.from.text);
  },
  true,
);

/**
 * The router calls this on Back or Forward in the history, before the old
 * screen goes. A screen with a back link is a detail: its title goes back
 * into the row that opened it.
 */
export function noteTraverse(fromHash, toHash) {
  const title = document.querySelector('#main .ag-title');
  const from = title && document.querySelector('#main .ag-back') ? box(title) : null;
  flight =
    from?.text && rowWords.get(fromHash) === from.text
      ? { dir: 'back', hash: toHash, row: fromHash, from, at: performance.now() }
      : null;
}

/** The flight for the screen at `hash`: 'in', 'back', or null. The screen change reads it (T1). */
export function flightOf(hash) {
  if (!flight || flight.hash !== hash || performance.now() - flight.at > 2000) return null;
  return flight.dir;
}

const moving = new WeakMap();

/** Run the flight after the new screen is in place (the router calls it after the scroll). */
export function land() {
  const f = flight;
  flight = null;
  if (!f || reduced.value || f.hash !== window.location.hash || performance.now() - f.at > 2000) return;
  let el = null;
  if (f.dir === 'in') {
    el = document.querySelector('#main .ag-title');
  } else {
    const link = [...document.querySelectorAll('#main a.ag-row-link')].find((a) => a.getAttribute('href') === f.row);
    el = link ? link.querySelector('.ag-row-title') : null;
  }
  if (!el || typeof el.animate !== 'function') return;
  const to = box(el);
  // Only the same words move. A screen with another title enters with the
  // rest of the work area (T1).
  if (!to.text || to.text !== f.from.text) {
    if (f.dir === 'in') {
      el.animate(
        [
          { opacity: 0, transform: 'translateY(8px)' },
          { opacity: 1, transform: 'none' },
        ],
        { duration: timing('change'), easing: ease() },
      );
    }
    return;
  }
  if (to.top > window.innerHeight || to.top < -to.size * 4) return;
  const before = moving.get(el);
  if (before) before.cancel();
  const scale = f.from.size / to.size;
  el.style.transformOrigin = '0 0';
  const anim = el.animate(
    [
      { transform: `translate(${f.from.left - to.left}px, ${f.from.top - to.top}px) scale(${scale})` },
      { transform: 'none' },
    ],
    { duration: timing('change'), easing: ease() },
  );
  moving.set(el, anim);
  const end = () => {
    if (moving.get(el) !== anim) return;
    moving.delete(el);
    el.style.transformOrigin = '';
  };
  anim.addEventListener('finish', end);
  anim.addEventListener('cancel', end);
}

// ----------------------------------------------- T4, the proof sets down

let setDown = null; // the root of a finding that the server just timestamped

/** Mark a finding that the server just timestamped. Its proof panel sets down one time. */
export function markSetDown(root) {
  setDown = root;
}

/** True one time for the finding that `markSetDown` named. */
export function takeSetDown(root) {
  if (!setDown || setDown !== root) return false;
  setDown = null;
  return true;
}

/**
 * Run a class recipe of css/motion.css one time on an element, and remove
 * the class when its animations end, so that `getAnimations()` is empty and
 * a later change of the element does not run it again.
 */
export function once(el, name) {
  if (!el || reduced.value) return;
  el.classList.remove(name);
  void el.offsetWidth;
  el.classList.add(name);
  const done = () => {
    if (el.getAnimations().some((a) => a.playState === 'running')) return;
    el.classList.remove(name);
    el.removeEventListener('animationend', done);
  };
  el.addEventListener('animationend', done);
}

// ----------------------------------------------------- L3, a row goes away

/** L3: opacity to 0 (press time), then height to 0 (change time). Resolves when the row can go. */
export async function leaveRow(el) {
  const fade = timing('press');
  const fold = timing('change');
  if (!fade || typeof el.animate !== 'function') return;
  const before = running.get(el);
  if (before) before.cancel();
  const height = el.getBoundingClientRect().height;
  el.style.overflow = 'hidden';
  const anim = el.animate(
    [
      { opacity: 1, height: `${height}px`, offset: 0 },
      { opacity: 0, height: `${height}px`, offset: fade / (fade + fold) },
      { opacity: 0, height: '0px', offset: 1 },
    ],
    { duration: fade + fold, easing: 'linear', fill: 'forwards' },
  );
  running.set(el, anim);
  await new Promise((done) => {
    anim.addEventListener('finish', done);
    anim.addEventListener('cancel', done);
  });
}

const frame = () =>
  new Promise((done) => {
    requestAnimationFrame(() => done());
  });

/**
 * Run a change of the screen. The work area enters with the CSS recipe T1
 * (css/motion.css), so the change itself is immediate here. The promise
 * resolves after the next paint.
 * @param {() => void} change sets signals
 * @param {{kind?: 'screen'|'detail'|'none', source?: Element|null}} [opts]
 */
export function transition(change, { kind = 'screen', source = null } = {}) {
  void kind;
  void source;
  change();
  return frame();
}

function animate(el, frames, ms) {
  const before = running.get(el);
  if (before) before.cancel();
  if (!ms || typeof el.animate !== 'function') return Promise.resolve();
  const overflow = el.style.overflow;
  el.style.overflow = 'hidden';
  const anim = el.animate(frames, { duration: ms, easing: ease() });
  running.set(el, anim);
  return new Promise((done) => {
    const end = () => {
      if (running.get(el) === anim) {
        running.delete(el);
        el.style.overflow = overflow;
      }
      done();
    };
    anim.addEventListener('finish', end);
    anim.addEventListener('cancel', end);
  });
}

/** Height motion (L1): the element opens from height 0. Cancels the running one. */
export function openHeight(el) {
  const height = el.getBoundingClientRect().height;
  return animate(
    el,
    [
      { height: '0px', opacity: 0 },
      { height: `${height}px`, opacity: 1 },
    ],
    timing('change'),
  );
}

/** Height motion: the element closes to height 0. The caller then removes it. */
export function closeHeight(el) {
  const height = el.getBoundingClientRect().height;
  return animate(
    el,
    [
      { height: `${height}px`, opacity: 1 },
      { height: '0px', opacity: 0 },
    ],
    timing('change'),
  );
}
