// Network matching: matching through the sealed matching service of the
// network (GET /api/enclave and the routes of shell/ui/routers/enclave.py).
// The screen shows one stage at a time: connect, write and approve the
// lines, then matching on. Proposals and introductions come first when
// there are any. A proposal shows its match type and the person's own lines
// only; a reveal shows the peer's card.
import { html, useLayoutEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { invalidate, useResource, mutate } from '../core/resource.js';
import { fmtTime } from '../core/format.js';
import { store } from '../core/store.js';
import {
  ActionButton,
  Card,
  Disclosure,
  ErrorLine,
  Facts,
  Field,
  Screen,
  Section,
  StatusLine,
  Switch,
  TextArea,
  TextInput,
} from '../components/index.js';

const STATE = '/api/enclave';
const CONSENT = '/api/enclave/consent';
const TYPES = [
  'research_fit',
  'method_help',
  'instrument_access',
  'data_material_share',
  'replication',
  'co_supervision',
];

function call(method, path, body) {
  return mutate(method, path, body, { invalidate: [STATE] });
}

const typeName = (type) => (TYPES.includes(type) ? t(`netmatch.type_${type}`) : type);

// ------------------------------------------------------------ connect

function Setup() {
  const [url, setUrl] = useState('');
  const [pins, setPins] = useState('');
  const [error, setError] = useState('');
  const save = async () => {
    let parsed;
    try {
      parsed = JSON.parse(pins);
    } catch {
      throw new Error(t('netmatch.pins_bad'));
    }
    await call('PUT', '/api/enclave/setup', { log_url: url, pins: parsed });
  };
  return html`
    <${Section} title=${t('netmatch.setup_title')}>
      <p class="rf-ui-help">${t('netmatch.setup_help')}</p>
      <${Field} id="nm-log" label=${t('netmatch.log_url')}><${TextInput} value=${url} onInput=${setUrl} /><//>
      <${Field} id="nm-pins" label=${t('netmatch.pins')} help=${t('netmatch.pins_help')}>
        <${TextArea} value=${pins} onInput=${setPins} rows=${6} />
      <//>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('netmatch.save')} busyLabel=${t('netmatch.saving')} run=${save} errorTo=${setError} />
      </div>
    <//>`;
}

// ------------------------------------------------------------ lines

const blank = () => ({ class: 'method', match_types: ['T1'], scope: 'both', text: '' });
const filled = (lines) => ({
  offers: lines.offers.filter((l) => l.text.trim()),
  wants: lines.wants.filter((l) => l.text.trim()),
});

/** The two lists of lines, as fields. `lines` and `setLines` belong to the parent. */
function LineFields({ lines, setLines }) {
  const edit = (side, i, text) =>
    setLines({ ...lines, [side]: lines[side].map((l, j) => (j === i ? { ...l, text } : l)) });
  const add = (side) => setLines({ ...lines, [side]: [...lines[side], blank()] });
  const side = (name) => html`
    <div class="ag-nm-side">
      <h3 class="ag-subtitle">${t(`netmatch.${name}`)}</h3>
      ${lines[name].map(
        (l, i) => html`
        <${Field} id=${`nm-${name}-${i}`} label=${t('netmatch.line', { n: i + 1 })} hideLabel>
          <${TextInput} value=${l.text} max=${140} onInput=${(v) => edit(name, i, v)} />
        <//>`,
      )}
      ${lines[name].length < 5 && html`<button type="button" class="rf-ui-button rf-ui-button--quiet" onClick=${() => add(name)}>${t('netmatch.add')}</button>`}
    </div>`;
  return html`<div class="ag-nm-lines">${side('offers')}${side('wants')}</div>`;
}

/** The lines as text, for a person whose lines are approved. */
function LineList({ draft }) {
  const side = (name) =>
    draft[name].length
      ? html`
      <div class="ag-nm-side">
        <h3 class="ag-subtitle">${t(`netmatch.${name}`)}</h3>
        <ul class="ag-nm-list">${draft[name].map((l) => html`<li>${l.text}</li>`)}</ul>
      </div>`
      : null;
  return html`<div class="ag-nm-lines">${side('offers')}${side('wants')}</div>`;
}

/** The promise of the network, and the days of an answer. */
function Pledge({ c }) {
  return html`
    <blockquote class="ag-quote">${c.statement}</blockquote>
    <p class="rf-ui-help">${t('netmatch.answer_days', {
      days: c.answer_days[c.answer_days.length - 1],
      first: c.answer_days[0],
      second: c.answer_days[1],
    })}</p>`;
}

/**
 * Stage 1: write the lines, read the promise, approve and start. One action
 * saves the lines, approves them with the statement on the screen, and
 * turns matching on. Nothing leaves before that click.
 */
function Start({ s }) {
  const consent = useResource(CONSENT);
  const [lines, setLines] = useState(() => {
    const d = s.draft || { offers: [], wants: [] };
    return {
      offers: d.offers.length ? d.offers : [blank()],
      wants: d.wants.length ? d.wants : [blank()],
    };
  });
  const [error, setError] = useState('');
  const c = consent.data.value;
  const ready = filled(lines).offers.length + filled(lines).wants.length > 0;
  const start = async () => {
    try {
      await mutate('PUT', '/api/enclave/draft', filled(lines));
      await mutate('POST', '/api/enclave/approve', { statement_hash: c.statement_hash });
      await call('POST', '/api/enclave/on', { on: true });
    } catch (err) {
      // The statement may have changed: show the current one and the current state.
      await invalidate([STATE, CONSENT]);
      throw err;
    }
    announce(t('netmatch.started'));
  };
  const draft = async () => {
    const out = await call('POST', '/api/enclave/draft');
    setLines({
      offers: out.draft.offers.length ? out.draft.offers : [blank()],
      wants: out.draft.wants.length ? out.draft.wants : [blank()],
    });
  };
  return html`
    <${Section} title=${t('netmatch.lines_title')}>
      <p class="rf-ui-help">${t('netmatch.lines_help')}</p>
      <${LineFields} lines=${lines} setLines=${setLines} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('netmatch.draft')} busyLabel=${t('netmatch.drafting')} run=${draft} errorTo=${setError} />
      </div>
    <//>
    <${Section} title=${t('netmatch.consent_title')}>
      ${c && html`<${Pledge} c=${c} />`}
      <${ErrorLine} text=${error || (consent.error.value ? consent.error.value.message : '')} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('netmatch.start')} busyLabel=${t('netmatch.starting')} run=${start} errorTo=${setError}
          disabled=${!c || !ready} />
      </div>
    <//>`;
}

/** Stage 2, the settings that a person rarely changes: the weekly cap, a check now. */
function WeeklyCap({ value }) {
  const consent = useResource(CONSENT);
  const [error, setError] = useState('');
  const c = consent.data.value;
  if (!c) return null;
  const options = Array.from({ length: c.weekly_cap_max }, (_, i) => i + 1);
  return html`
    <${Field} id="nm-cap" label=${t('netmatch.weekly_cap')} help=${t('netmatch.weekly_cap_help', { max: c.weekly_cap_max })}>
      <select id="nm-cap" class="rf-ui-input" value=${Math.min(value, c.weekly_cap_max)}
        onChange=${(e) => call('PUT', '/api/enclave/weekly-cap', { weekly_cap: Number(e.target.value) }).catch((x) => setError(x.message))}>
        ${options.map((n) => html`<option value=${n}>${n}</option>`)}
      </select>
    <//>
    <${ErrorLine} text=${error} />`;
}

/** Stage 2, a change of lines: the new lines go out only after a new approval. */
function Change({ s }) {
  const consent = useResource(CONSENT);
  const [lines, setLines] = useState(() => ({ offers: [...s.draft.offers], wants: [...s.draft.wants] }));
  const [error, setError] = useState('');
  const c = consent.data.value;
  const approve = async () => {
    await mutate('PUT', '/api/enclave/draft', filled(lines));
    await call('POST', '/api/enclave/approve', { statement_hash: c.statement_hash });
    announce(t('netmatch.changed'));
  };
  return html`
    <${LineFields} lines=${lines} setLines=${setLines} />
    ${c && html`<${Pledge} c=${c} />`}
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('netmatch.approve_new')} busyLabel=${t('netmatch.approving')} run=${approve} errorTo=${setError}
        disabled=${!c} />
    </div>`;
}

/** Stage 2: matching is on. The approved lines, and the quiet controls. */
function On({ s }) {
  const [error, setError] = useState('');
  return html`
    <${Section} title=${t('netmatch.on_title')}>
      <${StatusLine} state="active" text=${t('netmatch.on_status')} />
      ${!s.draft_approved && html`<${StatusLine} state="pending" text=${t('netmatch.draft_not_approved')} />`}
      <${LineList} draft=${s.draft} />
      <${Disclosure} kind="add" summary=${t('netmatch.change')}><${Change} s=${s} /><//>
      <${Disclosure} kind="add" summary=${t('netmatch.settings')}>
        <${WeeklyCap} value=${s.weekly_cap} />
        <div class="rf-ui-actions">
          <${ActionButton} kind="secondary" label=${t('netmatch.run')} busyLabel=${t('netmatch.running')}
            run=${() => call('POST', '/api/enclave/run')} errorTo=${setError} />
        </div>
        <${Switch} id="nm-on" label=${t('netmatch.on')} checked=${s.on}
          onChange=${(on) => call('POST', '/api/enclave/on', { on }).catch((e) => setError(e.message))} />
        <p class="rf-ui-help">${t('netmatch.off_help')}</p>
      <//>
      <${ErrorLine} text=${error} />
    <//>`;
}

// ------------------------------------------------------------ proposals

/** The card that goes to the other person after two yes answers. From the account; the person can change it. */
function ownCard() {
  const o = store.overview.value || {};
  return {
    name: o.name || '',
    institution: (o.institution && o.institution.name) || '',
    email: o.email || '',
    lab: (o.lab && o.lab.name) || '',
    orcid: o.orcid || '',
  };
}

const REQUIRED = ['name', 'institution', 'email'];

function Answer({ item }) {
  const [card, setCard] = useState(ownCard);
  const [editing, setEditing] = useState(() => REQUIRED.some((k) => !ownCard()[k]));
  const [error, setError] = useState('');
  const field = (k) => html`
    <${Field} id=${`nm-${item.id}-${k}`} label=${t(`netmatch.card_${k}`)}>
      <${TextInput} value=${card[k]} onInput=${(v) => setCard({ ...card, [k]: v })} />
    <//>`;
  const send = (choice) => () =>
    call('POST', '/api/enclave/answer', {
      proposal: item.id,
      choice,
      card: choice === 'yes' ? { ...card, lab: card.lab || null, orcid: card.orcid || null } : null,
    });
  const summary = [card.name, card.lab, card.institution, card.email, card.orcid].filter(Boolean).join(' · ');
  return html`
    <div class="ag-nm-card">
      <p class="rf-ui-help">${t('netmatch.card_intro')}</p>
      ${
        editing
          ? html`${field('name')}${field('institution')}${field('email')}${field('lab')}${field('orcid')}`
          : html`
          <p class="ag-nm-card-line">${summary}</p>
          <button type="button" class="rf-ui-button rf-ui-button--quiet" onClick=${() => setEditing(true)}>${t('netmatch.card_edit')}</button>`
      }
    </div>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('netmatch.yes')} run=${send('yes')} errorTo=${setError} />
      <${ActionButton} kind="secondary" label=${t('netmatch.not_now')} run=${send('not_now')} errorTo=${setError} />
      <${ActionButton} kind="quiet" label=${t('netmatch.no')} run=${send('no')} errorTo=${setError} />
    </div>`;
}

function Proposal({ item }) {
  const out = item.next_checkpoint && fmtTime(item.next_checkpoint);
  const chosen = item.choice !== 'unset' && item.choice !== 'sent';
  return html`
    <${Card} title=${t('netmatch.proposal', { type: typeName(item.type) })} meta=${t('netmatch.until', { date: fmtTime(item.answer_by) })}>
      <p class="rf-ui-help">${t('netmatch.reasons')}</p>
      <ul class="ag-nm-list">${item.reasons.map((r) => html`<li>${r}</li>`)}</ul>
      ${
        item.choice === 'sent'
          ? html`<p>${t('netmatch.sent')}</p>`
          : html`
          ${
            chosen
              ? html`<${StatusLine} state="pending" text=${t(`netmatch.chose_${item.choice}`, { date: out || '' })} />`
              : html`<p class="rf-ui-help">${t('netmatch.unset')}</p>`
          }
          <${Answer} item=${item} />`
      }
    <//>`;
}

// ------------------------------------------------------------ the meeting

const SEEN = 'anagram.met';

function seen(id) {
  try {
    const all = JSON.parse(localStorage.getItem(SEEN) || '[]');
    if (all.includes(id)) return true;
    localStorage.setItem(SEEN, JSON.stringify([...all, id].slice(-200)));
  } catch {
    // No storage: the motion plays each time. Nothing else depends on it.
  }
  return false;
}

/** A fixed shuffle of 0..n-1 from the text, so the same name always starts the same way. */
function shuffle(text, n) {
  const order = Array.from({ length: n }, (_, i) => i);
  let h = 2166136261;
  for (const ch of text) h = Math.imul(h ^ ch.charCodeAt(0), 16777619);
  for (let i = order.length - 1; i > 0; i -= 1) {
    h = Math.imul(h ^ (h >>> 15), 2246822507) >>> 0;
    const j = h % (i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order;
}

// Letters that stay whole when each one moves on its own. A name in a
// script that joins or stacks its letters (Arabic, Devanagari, ...) or with
// a separate accent mark shows as plain text, with no motion.
const SIMPLE = /^[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}\s.'’-]+$/u;
const MARK = /\p{M}/u;

function letters(name) {
  if (typeof Intl.Segmenter !== 'function') return null;
  const text = name.normalize('NFC');
  if (!SIMPLE.test(text) || MARK.test(text)) return null;
  return [...new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text)].map((g) => g.segment);
}

/**
 * The name of the other person, as an anagram that sorts itself: the
 * letters start in a shuffled order and move to their places, once for each
 * reveal (the first time this computer shows it). Only transform and opacity
 * move. After the motion, and with reduced motion, the name is plain text.
 * Screen readers read the plain name; the moving letters are hidden from them.
 */
function MetName({ id, name }) {
  const ref = useRef(null);
  const [moving, setMoving] = useState(() => {
    const parts = letters(name);
    if (!parts || !id || seen(id)) return null;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return null;
    return parts;
  });
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el || !moving) return;
    const spans = [...el.querySelectorAll('[data-l]')];
    const x = spans.map((l) => l.getBoundingClientRect().left);
    const order = shuffle(name, spans.length);
    const runs = spans.map((l, i) =>
      l.animate(
        [
          { transform: `translate(${x[order[i]] - x[i]}px, ${i % 2 ? -0.35 : 0.35}em)`, opacity: 0.25 },
          { transform: 'none', opacity: 1 },
        ],
        { duration: 900, delay: 120 + i * 28, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards' },
      ),
    );
    Promise.all(runs.map((r) => r.finished))
      .then(() => setMoving(null))
      .catch(() => setMoving(null));
  }, [moving]);
  if (!moving) return html`${name}`;
  // Words stay whole: a line breaks only between words.
  const words = [[]];
  moving.forEach((g, k) => {
    if (/\s/.test(g)) words.push(' ', []);
    else words[words.length - 1].push({ g, k });
  });
  return html`
    <span class="ag-nm-sr">${name}</span>
    <span class="ag-nm-name" ref=${ref} aria-hidden="true">${words.map((w) =>
      typeof w === 'string'
        ? w
        : html`<span class="ag-nm-word">${w.map(({ g, k }) => html`<span key=${k} data-l>${g}</span>`)}</span>`,
    )}</span>`;
}

function Reveal({ item }) {
  const p = item.card_of_peer;
  return html`
    <article class="ag-card ag-nm-met" aria-label=${t('netmatch.reveal', { name: p.name })}>
      <p class="ag-nm-met-lead">${t('netmatch.reveal_lead', { type: typeName(item.type) })}</p>
      <h3 class="ag-nm-met-name"><${MetName} id=${item.id} name=${p.name} /></h3>
      <${Facts} rows=${[
        [t('netmatch.peer_institution'), p.institution],
        [t('netmatch.peer_lab'), p.lab],
        [t('netmatch.peer_email'), p.email],
        [t('netmatch.peer_orcid'), p.orcid],
        [t('netmatch.node'), item.node?.affiliation],
      ]} />
    </article>`;
}

function Item({ item }) {
  if (item.kind === 'reveal') return html`<${Reveal} item=${item} />`;
  if (item.kind === 'proposal') return html`<${Proposal} item=${item} />`;
  return html`<${Card} title=${t('netmatch.ended')} />`;
}

// ------------------------------------------------------------ screen

function View() {
  const state = useResource(STATE, { topics: ['enclave.changed'] });
  return html`
    <${Screen} title=${t('netmatch.title')} lead=${t('netmatch.lead')} resources=${[state]}>
      ${() => {
        const s = state.data.value;
        if (!s.set_up) return html`<${Setup} />`;
        const cards = s.cards.filter((c) => c.kind !== 'empty');
        // Who you met first, then what waits for an answer; answers that went out fold away.
        const met = cards.filter((c) => c.kind === 'reveal');
        const open = cards.filter((c) => c.kind !== 'reveal' && c.choice !== 'sent');
        const sent = cards.filter((c) => c.kind === 'proposal' && c.choice === 'sent');
        return html`
          <p class="rf-ui-help" role="note">${t('netmatch.simulated')}</p>
          ${
            met.length + open.length + sent.length > 0 &&
            html`
            <${Section} title=${t('netmatch.cards_title')}>
              ${[...met, ...open].map((c) => html`<${Item} key=${c.id || c.kind} item=${c} />`)}
              ${
                sent.length > 0 &&
                html`
                <${Disclosure} kind="details" summary=${t('netmatch.sent_count', { n: sent.length })}>
                  ${sent.map((c) => html`<${Item} key=${c.id} item=${c} />`)}
                <//>`
              }
            <//>`
          }
          ${s.on ? html`<${On} s=${s} />` : html`<${Start} s=${s} />`}
          ${s.on && !cards.length && html`<p class="rf-ui-help">${t('netmatch.no_cards')}</p>`}`;
      }}
    <//>`;
}

export const screen = { id: 'netmatch', path: '/network-matching', nav: { group: 'main', order: 45 }, View };
