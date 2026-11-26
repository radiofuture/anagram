// Ask (track R4, step 15b): one screen, one input. With a model the answer
// streams with a number after each statement, and each number opens its
// source row. With no model the same input searches and the passages are the
// answer. The Home field opens this screen with `?q=`. The address then
// holds the thread (`#/ask/<thread>`), so a reload shows the same answer.
// With no question yet: the earlier questions, each one a new ask.
import { html, useEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { fmtTime } from '../core/format.js';
import { mutate, optional, useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { ActionButton, Screen, Section } from '../components/index.js';
import { ALL, AskForm, AskResult, Examples, useAsk, useAskSetup } from '../parts/ask.js';

const EARLIER = 8;

/** Keep the thread in the address, with no new history entry and no route change. */
function keep(thread) {
  window.history.replaceState(window.history.state, '', href('ask', { thread }));
}

function Earlier({ rows, onAsk }) {
  if (!rows?.length) return null;
  // A question asked again shows one time, at its newest place.
  const seen = new Set();
  rows = rows.filter((r) => !seen.has(r.question) && seen.add(r.question));
  const clear = () => mutate('DELETE', '/api/ask/history', null, { invalidate: ['/api/ask/history'] });
  return html`
    <${Section} id="ask-earlier" title=${t('ask.earlier')}>
      <ul class="ag-rows" aria-labelledby="ask-earlier">
        ${rows.slice(0, EARLIER).map(
          (r) => html`
          <li key=${r.id} class="ag-rows-item">
            <button type="button" class="ag-row-main ag-row-link ag-ask-again" onClick=${() => onAsk(r.question)}>
              <span class="ag-row-title">${r.question}</span>
              <span class="ag-row-meta">${fmtTime(r.at)}</span>
            </button>
          </li>`,
        )}
      </ul>
      <div class="rf-ui-actions">
        <${ActionButton} kind="quiet" label=${t('ask.clear')} busyLabel=${t('ask.clearing')} run=${clear} />
      </div>
    <//>`;
}

function View({ params, query }) {
  const setup = useAskSetup();
  const earlier = useResource('/api/ask/history', { topics: [['ask', 'done'].join('.')] });
  const { state, ask, restore } = useAsk();
  const [question, setQuestion] = useState(query.q || '');
  const [space, setSpace] = useState(query.space || ALL);
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    if (params.thread) {
      restore(params.thread).then((s) => {
        if (s) setQuestion(s.question);
      });
    } else if (query.q) {
      ask(query.q, query.space || ALL).then((thread) => {
        if (thread) keep(thread);
      });
    }
  }, []);
  const run = async (text, where = space) => {
    const q = (text || '').trim();
    if (!q) return;
    setQuestion(q);
    const thread = await ask(q, where);
    if (thread) keep(thread);
  };
  const ready = optional(setup);
  // The title is the label of the field; the field label is then for screen readers only.
  const title = ready ? t(ready.model !== null ? 'ask.label' : 'ask.label_search') : t('ask.title');
  return html`
    <${Screen} title=${title} resources=${[setup]}>
      ${() => {
        const info = optional(setup);
        const model = info.model !== null;
        const idle = state.phase === 'idle' || state.phase === 'gone';
        return html`
          <div class="ag-ask ag-ask--screen">
            <${AskForm} info=${info} question=${question} setQuestion=${setQuestion} space=${space}
              setSpace=${setSpace} busy=${state.phase === 'asking'} onSubmit=${run} hideLabel />
            ${state.phase === 'gone' && html`<p class="ag-empty">${t('ask.gone')}</p>`}
            ${!idle && html`<${AskResult} key=${state.thread || 'new'} state=${state} spaces=${info.spaces} model=${model} />`}
            ${
              idle &&
              html`
              <${Examples} info=${info} onPick=${(x) => run(x)} />
              <${Earlier} rows=${optional(earlier)} onAsk=${(q) => run(q)} />`
            }
          </div>`;
      }}
    <//>`;
}

export const screen = { id: 'ask', path: '/ask/:thread?', parent: 'home', View };
