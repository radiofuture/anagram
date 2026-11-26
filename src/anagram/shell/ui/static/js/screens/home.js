// Home: where the knowledge of the lab is. First the ask field (slot
// `home.ask`); then what is new and why it matters: the newest
// possible finding is the one task panel of the screen (the blue offset),
// with the reason and the next useful action; then the other new things as
// rows. A proposal that arrives while the screen is open sets down (motion
// recipe M1, css/screens/home.css), one time, on the real event.
import { html, useLayoutEffect, useRef } from '../core/html.js';
import { t } from '../core/copy.js';
import { store } from '../core/store.js';
import { cleanText, fmtRange, fmtTime } from '../core/format.js';
import { mutate, optional, useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { provided } from '../core/slots.js';
import { useAskSetup } from '../parts/ask.js';
import { ActionButton, Button, Empty, Row, RowList, Screen, Section, Slot, TaskPanel } from '../components/index.js';

const ASK = ['home', 'ask'].join('.');
const SECTIONS = ['home', 'sections'].join('.');

function newest(drafts) {
  const open = drafts.filter((d) => d.state !== 'later');
  open.sort((a, b) => String(b.end || '').localeCompare(String(a.end || '')));
  return open;
}

function Lead({ draft, more, fresh }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (fresh && ref.current) ref.current.classList.add('ag-m-setdown');
  }, [draft.id]);
  const settle = (e) => {
    const el = e.currentTarget;
    if (el.getAnimations().every((x) => x.playState === 'finished')) el.classList.remove('ag-m-setdown');
  };
  const claim = cleanText(draft.claim_suggestion);
  const later = () =>
    mutate(
      'POST',
      `/api/suggestions/${encodeURIComponent(draft.id)}`,
      { action: 'later' },
      { invalidate: ['/api/suggestions'] },
    );
  return html`
    <article class="ag-match ag-proof ag-lead-finding" ref=${ref} aria-labelledby="lead-title" onAnimationEnd=${settle}>
      <p class="ag-match-label">${t('home.lead_label')}</p>
      <h2 class="ag-match-name" id="lead-title">${claim || cleanText(draft.title)}</h2>
      <p class="ag-match-where">${[claim ? cleanText(draft.title) : null, fmtRange(draft.start, draft.end)].filter(Boolean).join(', ')}</p>
      ${draft.reason && html`<p class="ag-match-why">${cleanText(draft.reason)}</p>`}
      <div class="rf-ui-actions ag-match-actions">
        <a class="rf-ui-button" href=${href('draft', { id: draft.id })}>${t('home.lead_review')}</a>
        <${ActionButton} kind="secondary" label=${t('home.lead_later')} busyLabel=${t('home.lead_later')} run=${later} />
        ${more > 0 && html`<a class="ag-link" href=${href('library', { kind: 'findings' })}>${t('home.lead_more', { n: more })}</a>`}
      </div>
    </article>`;
}

function Line({ line }) {
  const params = { name: t('sharing.a_member'), ...line.params, n: line.params.n || 1 };
  return html`<${Row} title=${t(`home.${line.text_key}`, params)} meta=${fmtTime(line.at)}
    href=${href(line.screen, line.route || {})} />`;
}

// The first Home, with no source: what Anagram does from now on, and the one
// next action. After the last setup step the panel sets down one time
// (recipe T4: the cause is the save of the setup).
const FIRST = ['first_read', 'first_propose', 'first_people'];

function First() {
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (store.arrived.peek() && ref.current) ref.current.firstElementChild.classList.add('ag-m-proof');
    store.arrived.value = false;
  }, []);
  const settle = (e) => {
    const el = e.currentTarget.firstElementChild;
    if (el?.getAnimations().every((x) => x.playState === 'finished')) el.classList.remove('ag-m-proof');
  };
  return html`
    <div class="ag-first" ref=${ref} onAnimationEnd=${settle}>
      <${TaskPanel} label=${t('home.first_title')}>
        <ol class="ag-first-steps">
          ${FIRST.map((key) => html`<li key=${key}>${t(`home.${key}`)}</li>`)}
        </ol>
        <div class="rf-ui-actions">
          <${Button} href=${href('sources')}>${t('home.connect')}<//>
        </div>
      <//>
    </div>`;
}

function View() {
  const sources = useResource('/api/sources', { topics: ['source'], throttle: 2000 });
  const proposals = useResource('/api/suggestions', { topics: ['draft.changed', 'suggestion'] });
  // The activity route is R7's; other events reload it.
  const activity = useResource('/api/activity', {
    topics: ['shared', 'share', 'source.added'],
  });
  const seen = useRef(null);
  const ask = provided(ASK).length > 0;
  const empty = Boolean(sources.data.value && !sources.data.value.sources.length);
  // One heading that names the task of the state: the ask field has no
  // label of its own on Home (W12).
  const askSetup = useAskSetup();
  const setup = ask ? optional(askSetup) : null;
  let title = t('home.title');
  if (empty) title = t('home.first_title');
  else if (setup) title = t(setup.model !== null ? 'home.title_ask' : 'home.title_search');
  return html`
    <${Screen} title=${title} resources=${[sources]}>
      ${() => {
        if (empty) return html`<${First} />`;
        const open = newest(optional(proposals) || []);
        const lead = open[0] || null;
        if (proposals.data.value !== null && seen.current === null) seen.current = lead ? lead.id : '';
        const fresh = lead !== null && seen.current !== null && seen.current !== lead.id;
        // The lead panel says the proposals; the rows say the rest.
        const lines = (optional(activity) || []).filter((l) => l.type !== 'suggestion.new');
        return html`
          <${Slot} name=${ASK} />
          <${Section} id="new-title" title=${t('home.new_title')}>
            ${lead && html`<${Lead} key=${lead.id} draft=${lead} more=${open.length - 1} fresh=${fresh} />`}
            <${RowList} items=${lines} keyOf=${(l) => `${l.type} ${l.at}`} label=${t('home.new_title')}
              render=${(l) => html`<${Line} line=${l} />`}
              empty=${lead ? null : html`<${Empty} text=${t(ask ? 'home.nothing_new_ask' : 'home.nothing_new')} />`} />
          <//>
          <${Slot} name=${SECTIONS} />`;
      }}
    <//>`;
}

export const screen = { id: 'home', path: '/home', nav: { group: 'main', order: 10 }, View };
