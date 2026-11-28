// Ask and search: the parts that the Home field (slot `home.ask`)
// and the Ask screen (`#/ask`) share. One input: with a model it asks, with
// no model it searches, and the passages are the answer.
//
// An answer comes as live events on the one stream (`ask.sources`,
// `ask.delta`, `ask.done`, `ask.error`, key = the thread id of
// `POST /api/ask`). The sources come first; the text grows as it arrives;
// each [n] in the text is a button that goes to its source row.
import { html, useEffect, useRef, useState } from '../core/html.js';
import { t, tx } from '../core/copy.js';
import { api } from '../core/api.js';
import { on } from '../core/events.js';
import { cleanText, fmtDate } from '../core/format.js';
import { useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { KindLabel, ErrorLine, StatusLine } from '../components/index.js';

export const ALL = 'all';

// Events can come before the answer of POST /api/ask: keep them by thread.
const early = new Map();
on('ask.*', (event) => {
  const thread = event.key || event.data?.thread;
  if (!thread) return;
  const list = early.get(thread) || [];
  list.push(event);
  early.set(thread, list.slice(-400));
  if (early.size > 20) early.delete(early.keys().next().value);
});

export const START = {
  thread: null,
  phase: 'idle',
  question: '',
  sources: null,
  text: '',
  done: null,
  error: '',
  leftOut: 0,
};

function reduce(state, event) {
  const d = event.data || {};
  const kind = event.type.split('.')[1]; // the part after `ask.`
  if (kind === 'sources') return { ...state, sources: d.sources || [], leftOut: d.left_out || 0 };
  if (kind === 'delta') return { ...state, text: state.text + (d.text || '') };
  if (kind === 'done') return { ...state, phase: 'done', done: d, text: d.text || '', leftOut: d.left_out || 0 };
  if (kind === 'error') return { ...state, phase: 'error', error: d.message || t('common.failed') };
  return state;
}

/** The record of `GET /api/ask/{thread}` as a state. */
function restored(thread, got) {
  const phase = got.state === 'done' ? 'done' : got.state === 'error' ? 'error' : 'asking';
  const done = phase === 'done' ? { mode: got.mode, grounded: got.grounded, text: got.answer } : null;
  return {
    ...START,
    thread,
    phase,
    done,
    question: got.question || '',
    sources: got.sources || [],
    text: got.answer || '',
    leftOut: got.left_out || 0,
    error: phase === 'error' ? t('common.failed') : '',
  };
}

/** The setup of the field: the model (or none), the spaces, the examples. */
export function useAskSetup() {
  return useResource('/api/ask/setup', {
    topics: [['models', 'state'].join('.'), 'item.kind', 'source.added'],
    throttle: 2000,
  });
}

/**
 * The state of one answer and the actions on it.
 * `ask(question, space)` starts an answer and gives the thread id.
 * `restore(thread)` shows an answer of this session again (a reload).
 */
export function useAsk() {
  const [state, setState] = useState(START);
  const current = useRef(null);
  useEffect(
    () =>
      on('ask.*', (event) => {
        const thread = event.key || event.data?.thread;
        if (thread && thread === current.current) setState((s) => reduce(s, event));
      }),
    [],
  );
  const ask = async (question, space) => {
    const q = (question || '').trim();
    if (!q) return null;
    current.current = null;
    setState({ ...START, phase: 'asking', question: q });
    try {
      const out = await api('POST', '/api/ask', { question: q, space });
      current.current = out.thread;
      let s = { ...START, thread: out.thread, phase: 'asking', question: q };
      for (const event of early.get(out.thread) || []) s = reduce(s, event);
      early.delete(out.thread);
      setState(s);
      return out.thread;
    } catch (err) {
      setState({ ...START, phase: 'error', question: q, error: err.message });
      return null;
    }
  };
  const restore = async (thread) => {
    current.current = thread;
    try {
      const got = await api('GET', `/api/ask/${encodeURIComponent(thread)}`);
      let s = restored(thread, got);
      for (const event of early.get(thread) || []) s = reduce(s, event);
      setState(s);
      return s;
    } catch (err) {
      current.current = null;
      setState({ ...START, phase: 'gone', error: err.message });
      return null;
    }
  };
  return { state, ask, restore };
}

/** The word for a space: none for the person's own library, else the lab name. */
export function placeName(spaces, space) {
  if (!space || space === 'private') return null;
  const row = (spaces || []).find((s) => s.id === space);
  return row?.label || t('ask.lab');
}

/**
 * The choice of the place: only when this computer can read more than one.
 * Quiet text choices on one line (native radios; the chosen one has the
 * lime edge of a tab), not a native select (W13).
 */
export function PlaceSelect({ id, spaces, value, onChange }) {
  if (!spaces || spaces.length < 2) return null;
  const options = [
    { id: ALL, label: t('ask.everywhere') },
    ...spaces.map((s) => ({ id: s.id, label: s.id === 'private' ? t('ask.only_you') : s.label || t('ask.lab') })),
  ];
  return html`
    <fieldset class="ag-ask-where" id=${id}>
      <legend>${t('ask.where')}</legend>
      ${options.map(
        (o) => html`
        <label key=${o.id} class="ag-place" data-on=${String(o.id === value)}>
          <input type="radio" name=${`${id}-place`} value=${o.id} checked=${o.id === value}
            onChange=${() => onChange(o.id)} />
          <span>${o.label}</span>
        </label>`,
      )}
    </fieldset>`;
}

/** The one input. With no model the same input searches. */
export function AskForm({ info, question, setQuestion, space, setSpace, busy, onSubmit, hideLabel }) {
  const model = info.model !== null;
  const submit = (e) => {
    e.preventDefault();
    onSubmit(question, space);
  };
  const setupLink = html`<a href=${href('account', {}, { section: 'models-title' })}>${t('ask.setup_link')}</a>`;
  return html`
    <form class="ag-ask-form" role="search" aria-labelledby="ask-label" onSubmit=${submit}>
      <label id="ask-label" for="ask-q" class=${hideLabel ? 'rf-ui-sr-only' : 'ag-ask-label'}>${t(model ? 'ask.label' : 'ask.label_search')}</label>
      <div class="ag-ask-row">
        <input id="ask-q" class="rf-ui-input ag-ask-input" type="search" value=${question} maxlength="500"
          autocomplete="off" spellcheck=${false} enterkeyhint=${model ? 'go' : 'search'}
          onInput=${(e) => setQuestion(e.currentTarget.value)} />
        <button type="submit" class="rf-ui-button ag-ask-go" aria-disabled=${busy ? 'true' : undefined}>
          ${t(model ? 'ask.go' : 'ask.go_search')}
        </button>
      </div>
      <${PlaceSelect} id="ask-space" spaces=${info.spaces} value=${space} onChange=${setSpace} />
      ${!model && html`<p class="rf-ui-help ag-ask-setup">${tx('ask.no_model', { link: setupLink })}</p>`}
    </form>`;
}

/** Up to three titles of the person's newest findings, as questions to try. */
export function Examples({ info, onPick }) {
  if (!info.examples?.length) return null;
  return html`
    <div class="ag-ask-try">
      <p class="rf-ui-help" id="ask-try">${t('ask.try')}</p>
      <ul class="ag-plain" aria-labelledby="ask-try">
        ${info.examples.map((x) => html`<li key=${x}><button type="button" class="ag-link" onClick=${() => onPick(x)}>${x}</button></li>`)}
      </ul>
    </div>`;
}

/** The answer text with each [n] as a button that goes to source n. */
function Answer({ text, count, onCite }) {
  const parts = text.split(/(\[\d+\])/);
  return html`
    <p class="ag-answer">
      ${parts.map((part, i) => {
        const m = /^\[(\d+)\]$/.exec(part);
        const n = m ? Number(m[1]) : 0;
        if (!m || n < 1 || n > count) return part;
        return html`<button type="button" key=${i} class="ag-cite" aria-label=${t('ask.cite', { n })}
          onClick=${() => onCite(n)}>${n}</button>`;
      })}
    </p>`;
}

function Sources({ sources, lit, spaces }) {
  return html`
    <ol class="ag-rows ag-sources" aria-label=${t('ask.sources')}>
      ${sources.map((s) => {
        const meta = [
          html`<${KindLabel} kind=${s.kind} />`,
          placeName(spaces, s.space),
          s.time ? fmtDate(s.time) : null,
          s.third_party ? t('ask.third_party') : null,
        ].filter(Boolean);
        return html`
          <li key=${s.n} id=${`ask-src-${s.n}`} class="ag-rows-item ag-source" data-lit=${lit === s.n ? 'true' : undefined}>
            <a class="ag-source-main" href=${href('item', { id: s.item_ref })}>
              <span class="ag-source-n" aria-hidden="true">${s.n}</span>
              <span class="ag-source-body">
                <span class="ag-row-title">${cleanText(s.title) || t('ask.untitled')}</span>
                <span class="ag-row-meta">${meta.map((m, i) => html`<span key=${i} class="ag-source-fact">${m}</span>`)}</span>
                <span class="ag-row-note">${cleanText(s.text)}</span>
              </span>
            </a>
          </li>`;
      })}
    </ol>`;
}

/** The answer: a status line while it comes, the text, then the sources. */
export function AskResult({ state, spaces, model }) {
  const [lit, setLit] = useState(0);
  const sources = state.sources || [];
  const cite = (n) => {
    setLit(n);
    const el = document.querySelector(`#ask-src-${n} a`);
    if (el) {
      el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      el.focus({ preventScroll: true });
    }
  };
  const passages = state.done && state.done.mode === 'passages';
  const answering = model && state.phase === 'asking' && state.sources !== null;
  let status = null;
  if (state.phase === 'asking' && state.sources === null) status = t(model ? 'ask.looking' : 'ask.searching');
  else if (answering && !state.text && sources.length) status = t('ask.writing', { n: sources.length });
  const notes = [];
  if (state.done && state.done.mode === 'answer' && state.done.grounded === false) notes.push(t('ask.not_grounded'));
  if (state.leftOut > 0 && (state.phase === 'done' || state.phase === 'error'))
    notes.push(t('ask.left_out', { n: state.leftOut }));
  const nothing = state.sources !== null && !sources.length && state.phase !== 'asking';
  return html`
    <div class="ag-ask-result" aria-live="polite" aria-busy=${state.phase === 'asking' ? 'true' : 'false'}>
      <${StatusLine} state="pending" text=${status} />
      ${!passages && state.text && html`<${Answer} text=${state.text} count=${sources.length} onCite=${cite} />`}
      <${ErrorLine} text=${state.error} />
      ${nothing && html`<p class="ag-empty">${t('ask.nothing')}</p>`}
      ${notes.map((n) => html`<p class="rf-ui-help" key=${n}>${n}</p>`)}
      ${
        sources.length > 0 &&
        html`
        <h2 class="ag-ask-head">${t(passages || !model ? 'ask.passages' : 'ask.sources')}</h2>
        <${Sources} sources=${sources} lit=${lit} spaces=${spaces} />`
      }
    </div>`;
}
