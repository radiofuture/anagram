// Sharing, in three views (`#/sharing/:tab?`): what other people shared
// with you, what you shared and who opened it, and your rings. Track R5 owns
// this screen (step 7c). The history of one person is `history.js`; the
// share sheet and "Shared with" on a finding are `slots/share.js`.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { search } from '../core/api.js';
import { fmtDate } from '../core/format.js';
import { href } from '../core/router.js';
import { mutate, useResource } from '../core/resource.js';
import {
  ActionButton,
  ChipList,
  Disclosure,
  Empty,
  ErrorLine,
  Row,
  RowList,
  Screen,
  SearchSelect,
} from '../components/index.js';
import { StateLine, personName } from '../parts/shares.js';

const RING_HELP = {
  'My lab': 'ring_lab',
  Collaborators: 'ring_collaborators',
  Community: 'ring_community',
  Public: 'ring_public',
};
const FIXED = new Set(['Public', 'Community']);

// ------------------------------------------------------------ shared with me

const keyOf = (g) => g.grant_id || `invite:${g.invite_id}`;
const reader = (g) => `/reader/#${encodeURIComponent(g.grant_id)}`;
const titleOf = (g) => g.title || t('sharing.untitled', { sender: g.sender });

/** One received finding. The reading view is a full page; it records the read. */
function Received({ g, children }) {
  if (!g.grant_id) {
    return html`<${Row} title=${titleOf(g)} note=${t('sharing.waiting_send')} />`;
  }
  // The sender shows one time: in the title until the first open, then in the facts.
  const meta = g.title
    ? t('sharing.from', { sender: g.sender, date: fmtDate(g.received_at) })
    : t('sharing.shared_on', { date: fmtDate(g.received_at) });
  if (!g.ready) return html`<${Row} title=${titleOf(g)} meta=${meta} note=${t('sharing.other_device')} />`;
  let note = null;
  if (g.withdrawn) note = t('sharing.withdrawn', { sender: g.sender });
  else if (!g.opened_at) note = t('sharing.not_opened');
  return html`<${Row} title=${titleOf(g)} meta=${meta} note=${note} href=${reader(g)}>${children}<//>`;
}

/** A finding that includes others: its parts open from its row. */
function Parts({ parts }) {
  if (!parts.length) return null;
  return html`
    <ul class="ag-plain ag-share-parts" aria-label=${t('sharing.parts')}>
      ${parts.map(
        (p) => html`
        <li key=${keyOf(p)}><a class="ag-small-link" href=${reader(p)}>${titleOf(p)}</a></li>`,
      )}
    </ul>`;
}

function WithMe({ rows }) {
  const ids = new Set(rows.map((g) => g.grant_id).filter(Boolean));
  const top = rows.filter((g) => !(g.set?.parent && ids.has(g.set.parent)));
  const partsOf = (g) => rows.filter((p) => p.set && p.set.parent === g.grant_id && g.grant_id);
  return html`
    ${rows.length > 0 && html`<p class="rf-ui-help ag-share-notice">${t('sharing.record_notice')}</p>`}
    <${RowList} items=${top} keyOf=${keyOf} label=${t('sharing.tab_with_me')}
      render=${(g) => html`<${Received} g=${g}><${Parts} parts=${partsOf(g)} /><//>`}
      empty=${html`<${Empty} text=${t('sharing.with_me_empty')} />`} />`;
}

// -------------------------------------------------------------- shared by me

function groups(rows) {
  const out = new Map();
  for (const r of rows) {
    if (!out.has(r.finding.id)) out.set(r.finding.id, { id: r.finding.id, finding: r.finding, rows: [] });
    out.get(r.finding.id).rows.push(r);
  }
  return [...out.values()];
}

function People({ rows }) {
  return html`
    <ul class="ag-plain ag-share-people">
      ${rows.map(
        (r) => html`
        <li key=${r.target}>
          ${
            r.person.subject
              ? html`<a href=${href('history', { subject: r.person.subject })}>${personName(r)}</a>`
              : html`<span>${personName(r)}</span>`
          }
          <span class="ag-row-meta"><${StateLine} row=${r} /></span>
        </li>`,
      )}
    </ul>`;
}

function ByMe({ rows }) {
  return html`
    <${RowList} items=${groups(rows)} keyOf=${(g) => g.id} label=${t('sharing.tab_by_me')}
      render=${(g) => html`
        <${Row} title=${g.finding.title} href=${href('finding', { root: g.finding.root })}>
          <${People} rows=${g.rows} />
        <//>`}
      empty=${html`<${Empty} text=${t('sharing.by_me_empty')} action=${{ href: href('library'), label: t('sharing.open_library') }} />`} />`;
}

// --------------------------------------------------------------------- rings

function AddPerson({ ring, index }) {
  const [chosen, setChosen] = useState(null);
  const [error, setError] = useState('');
  const add = async () => {
    if (!chosen) throw new Error(t('sharing.choose_person'));
    await mutate(
      'POST',
      `/api/rings/${encodeURIComponent(ring.name)}/members`,
      { member: chosen.id },
      { invalidate: ['/api/rings'] },
    );
  };
  return html`
    <${Disclosure} kind="add" summary=${t('sharing.add_to', { ring: ring.name })}>
      <${SearchSelect} id=${`ring-add-${index}`} label=${t('sharing.add_label')} placeholder=${t('sharing.add_placeholder')}
        search=${(q, signal) => search(`/api/people?q=${encodeURIComponent(q)}`, signal)}
        onChange=${(s) => setChosen(s.selected)} />
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('sharing.add_action', { ring: ring.name })}
          busyLabel=${t('sharing.add_busy')} run=${add} errorTo=${setError} />
      </div>
    <//>`;
}

function Ring({ ring, index }) {
  const [error, setError] = useState('');
  const remove = async (m) => {
    setError('');
    try {
      await mutate(
        'POST',
        `/api/rings/${encodeURIComponent(ring.name)}/members/remove`,
        { member: m.id },
        { invalidate: ['/api/rings'] },
      );
    } catch (err) {
      setError(err.message);
    }
  };
  const fixed = FIXED.has(ring.name);
  return html`
    <li class="ag-ring" data-inner=${index === 0 ? 'true' : undefined}>
      <h3 class="ag-card-title">${ring.name}</h3>
      <p class="rf-ui-help">${t(`sharing.${RING_HELP[ring.name] || 'ring_other'}`)}</p>
      <${ChipList} items=${ring.members} label=${t('sharing.people_in', { ring: ring.name })}
        onRemove=${fixed ? null : remove} removeLabel=${(m) => t('sharing.remove', { name: m.label, ring: ring.name })}
        empty=${t('sharing.ring_empty')} />
      ${!fixed && html`<${AddPerson} ring=${ring} index=${index} />`}
      <${ErrorLine} text=${error} />
    </li>`;
}

function Rings({ rings }) {
  return html`
    <p class="rf-ui-help">${t('sharing.rings_lead')}</p>
    <ol class="ag-rings">
      ${rings.map((r, i) => html`<${Ring} key=${r.name} ring=${r} index=${i} />`)}
    </ol>`;
}

// -------------------------------------------------------------------- screen

const TABS = ['with-me', 'by-me', 'rings'];

function Tabs({ current, counts }) {
  return html`
    <nav class="ag-tabs" aria-label=${t('sharing.views')}>
      <ul>
        ${TABS.map(
          (tab) => html`
          <li key=${tab}>
            <a href=${href('sharing', { tab: tab === TABS[0] ? undefined : tab })}
              aria-current=${current === tab ? 'page' : undefined}>
              ${t(`sharing.tab_${tab.replace('-', '_')}`)}
              ${counts[tab] ? html` <span class="ag-tab-count">${counts[tab]}</span>` : null}
            </a>
          </li>`,
        )}
      </ul>
    </nav>`;
}

// Review P1-3: a person joined with a reader invite. The owner says yes
// before the finding goes. One question for each claim, then it goes away.
function Claims() {
  const claims = useResource('/api/reader-claims', { topics: ['share'] });
  const rows = claims.data.value || [];
  const [error, setError] = useState('');
  if (!rows.length) return null;
  const answer = (id, give) => () =>
    mutate(
      'POST',
      `/api/reader-claims/${encodeURIComponent(id)}`,
      { give },
      { invalidate: ['/api/reader-claims', '/api/history'] },
    );
  return html`
    <section class="ag-claims" aria-labelledby="claims-title">
      <h2 class="ag-section" id="claims-title">${t('sharing.claims_title')}</h2>
      <${ErrorLine} text=${error} />
      ${rows.map(
        (r) => html`
        <div class="ag-claim" key=${r.id}>
          <p>${t('sharing.claim_text', { name: r.name, email: r.email || t('sharing.claim_no_email'), contact: r.contact || '' })}</p>
          <div class="rf-ui-actions">
            <${ActionButton} label=${t('sharing.claim_give')} run=${answer(r.id, true)} errorTo=${setError} />
            <${ActionButton} kind="secondary" label=${t('sharing.claim_refuse')} run=${answer(r.id, false)} errorTo=${setError} />
          </div>
        </div>`,
      )}
    </section>`;
}

function View({ params }) {
  const tab = TABS.includes(params.tab) ? params.tab : TABS[0];
  const shared = useResource('/api/shared', { topics: ['shared'] });
  const history = useResource('/api/history', { topics: ['share', 'finding.changed'] });
  const rings = useResource('/api/rings', { topics: ['ring.changed'] });
  const unopened = (shared.data.value || []).filter((g) => g.grant_id && g.ready && !g.opened_at).length;
  const need = { 'with-me': [shared], 'by-me': [history], rings: [rings] }[tab];
  return html`
    <${Screen} title=${t('sharing.title')} resources=${need}>
      ${() => html`
        <${Claims} />
        <${Tabs} current=${tab} counts=${{ 'with-me': unopened }} />
        ${tab === 'with-me' && html`<${WithMe} rows=${shared.data.value} />`}
        ${tab === 'by-me' && html`<${ByMe} rows=${history.data.value} />`}
        ${tab === 'rings' && html`<${Rings} rings=${rings.data.value} />`}`}
    <//>`;
}

export const screen = { id: 'sharing', path: '/sharing/:tab?', nav: { group: 'main', order: 30 }, View };
