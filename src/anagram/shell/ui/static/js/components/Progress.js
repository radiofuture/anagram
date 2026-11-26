// Live work. Progress is determinate only: a bar with square ends whose width
// is done / total, and it moves only when a real event arrives (motion recipe
// P1). With no total it shows the name of the real work and no bar (P2).
// After 30 s with no change, the line says what the work waits for (P3).
// When the work is done, the settled fact replaces it (P4, `Settled`).
// There is no spinner and no pulse.
//
// RollingNumber and Count use the brand digit recipe (MOTION.md "Rolling
// numbers"): only the digits that change move, in fixed slots. The digits
// that move are hidden from assistive technology; the real value is text.
import { html, useEffect, useLayoutEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { ease, once, timing } from '../core/motion.js';
import { store } from '../core/store.js';

let rolls = 0;

function Digits({ value }) {
  const text = String(value);
  const shown = useRef(text);
  const ref = useRef(null);
  const [roll, setRoll] = useState(null); // { from, up, n }
  useLayoutEffect(() => {
    if (shown.current === text) return;
    const from = shown.current;
    shown.current = text;
    rolls += 1;
    setRoll(timing('number') ? { from, up: Number(text) >= Number(from), n: rolls } : null);
  }, [text]);
  useLayoutEffect(() => {
    if (!roll || !ref.current) return undefined;
    const ms = timing('number');
    const far = roll.up ? '100%' : '-100%';
    const near = roll.up ? '-100%' : '100%';
    const moves = [];
    for (const el of ref.current.querySelectorAll('[data-roll="new"]')) {
      moves.push(
        el.animate([{ transform: `translateY(${far})` }, { transform: 'none' }], { duration: ms, easing: ease() }),
      );
    }
    for (const el of ref.current.querySelectorAll('[data-roll="old"]')) {
      moves.push(
        el.animate([{ transform: 'none' }, { transform: `translateY(${near})` }], {
          duration: ms,
          easing: ease(),
          fill: 'forwards',
        }),
      );
    }
    const timer = setTimeout(() => setRoll(null), ms);
    // A new value replaces the motion in progress.
    return () => {
      clearTimeout(timer);
      for (const move of moves) move.cancel();
    };
  }, [roll]);
  const now = [...text];
  const old = roll ? [...roll.from.padStart(text.length, ' ')].slice(-text.length) : null;
  return html`
    <span class="rf-ui-number ag-number" ref=${ref}>
      ${now.map((digit, i) => {
        const moved = old && old[i] !== digit;
        return html`
          <span class="rf-ui-digit" key=${now.length - i}>
            ${moved && html`<span class="rf-ui-digit-old" data-roll="old" key=${`old-${roll.n}`}>${old[i]}</span>`}
            <span data-roll=${moved ? 'new' : undefined} key=${moved ? `new-${roll.n}` : 'now'}>${digit}</span>
          </span>`;
      })}
    </span>`;
}

/** A number that rolls when it changes. `label` is the value as text for assistive technology. */
export function RollingNumber({ value, label }) {
  return html`
    <span class="ag-count">
      <span class="rf-ui-sr-only">${label === undefined ? String(value) : label}</span>
      <span aria-hidden="true"><${Digits} value=${value} /></span>
    </span>`;
}

/** A phrase with one number that rolls: `<${Count} n=${12} text=${t('sources.items', { n: 12 })} />`. */
export function Count({ n, text }) {
  const at = text.indexOf(String(n));
  if (at < 0) return text;
  return html`
    <span class="ag-count">
      <span class="rf-ui-sr-only">${text}</span>
      <span aria-hidden="true">${text.slice(0, at)}<${Digits} value=${n} />${text.slice(at + String(n).length)}</span>
    </span>`;
}

function Bar({ done, total, label }) {
  const ref = useRef(null);
  const ratio = total > 0 ? Math.max(0, Math.min(1, done / total)) : 0;
  useLayoutEffect(() => {
    if (ref.current) ref.current.style.setProperty('--ag-progress', String(ratio));
  }, [ratio]);
  return html`
    <div class="ag-progress-track" role="progressbar" aria-label=${label}
      aria-valuemin="0" aria-valuemax=${total} aria-valuenow=${Math.min(done, total)}>
      <span class="ag-progress-bar" ref=${ref}></span>
    </div>`;
}

/**
 * `{ done, total, label, detail? }`, or `{ job }` with the id of a job from
 * `job.progress` events. `label` is the text line. With `total === null`
 * there is no bar.
 */
const STALL_MS = 30000;

/** True after `ms` with no change of `mark`. A change sets it false again. */
function useStalled(mark, ms, on) {
  const [stalled, setStalled] = useState(false);
  useEffect(() => {
    setStalled(false);
    if (!on) return undefined;
    const timer = setTimeout(() => setStalled(true), ms);
    return () => clearTimeout(timer);
  }, [mark, on]);
  return stalled;
}

/**
 * The settled fact after live work (P4): it replaces the progress line with
 * an opacity change, one time, when `busy` becomes false.
 */
export function Settled({ busy, children }) {
  const was = useRef(busy);
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (was.current && !busy && ref.current) once(ref.current, 'ag-m-swap');
    was.current = busy;
  }, [busy]);
  if (busy) return null;
  return html`<span class="ag-settled" ref=${ref}>${children}</span>`;
}

export function Progress({ done, total, label, detail, job, waitFor }) {
  const stalled = useStalled(`${done}/${total}`, STALL_MS, Boolean(waitFor) && !job);
  let view = { done, total, label, detail };
  if (job) {
    const live = store.live.jobs.value[job];
    if (!live || live.state === 'done') return null;
    if (live.state === 'failed')
      return html`<p class="rf-ui-error" role="alert">${live.error || t('common.failed')}</p>`;
    view = { done: live.done, total: live.total, label: t(live.label_key, { done: live.done, total: live.total }) };
  }
  const known = view.total !== null && view.total !== undefined;
  const line = stalled ? html`<span class="ag-m-swap" key="wait">${waitFor}</span>` : view.label;
  return html`
    <div class="ag-progress">
      <p class="ag-progress-label">${line}</p>
      ${known && html`<${Bar} done=${view.done || 0} total=${view.total} label=${typeof view.label === 'string' ? view.label : t('common.progress')} />`}
      ${view.detail && html`<p class="rf-ui-help ag-progress-detail">${view.detail}</p>`}
    </div>`;
}
