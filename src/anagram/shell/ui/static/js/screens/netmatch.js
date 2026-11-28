// Network matching: matching through the sealed matching service of the
// network (GET /api/enclave and the routes of shell/ui/routers/enclave.py).
// Set up, lines, consent, on and off, then the cards: a proposal shows its
// match type and the person's own lines only; a reveal shows the peer's card.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { useResource, mutate } from '../core/resource.js';
import { fmtDate, fmtTime } from '../core/format.js';
import {
  ActionButton,
  Card,
  ErrorLine,
  Facts,
  Field,
  Screen,
  Section,
  Switch,
  TextArea,
  TextInput,
} from '../components/index.js';

const STATE = '/api/enclave';
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

function Lines({ draft }) {
  const [lines, setLines] = useState({ offers: draft ? draft.offers : [], wants: draft ? draft.wants : [] });
  const [error, setError] = useState('');
  const edit = (side, i, text) =>
    setLines({ ...lines, [side]: lines[side].map((l, j) => (j === i ? { ...l, text } : l)) });
  const add = (side) =>
    setLines({ ...lines, [side]: [...lines[side], { class: 'method', match_types: ['T1'], scope: 'both', text: '' }] });
  const side = (name) => html`
    <h3 class="ag-subtitle">${t(`netmatch.${name}`)}</h3>
    ${lines[name].map(
      (l, i) => html`
      <${Field} id=${`nm-${name}-${i}`} label=${t('netmatch.line', { n: i + 1 })} hideLabel>
        <${TextInput} value=${l.text} max=${140} onInput=${(v) => edit(name, i, v)} />
      <//>`,
    )}
    ${lines[name].length < 5 && html`<button type="button" class="rf-ui-button rf-ui-button--quiet" onClick=${() => add(name)}>${t('netmatch.add')}</button>`}`;
  return html`
    <${Section} title=${t('netmatch.lines_title')}>
      <p class="rf-ui-help">${t('netmatch.lines_help')}</p>
      ${side('offers')}
      ${side('wants')}
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('netmatch.draft')} busyLabel=${t('netmatch.drafting')}
          run=${async () => {
            const s = await call('POST', '/api/enclave/draft');
            setLines(s.draft);
          }} errorTo=${setError} />
        <${ActionButton} label=${t('netmatch.save')} busyLabel=${t('netmatch.saving')}
          run=${() => call('PUT', '/api/enclave/draft', lines)} errorTo=${setError} />
      </div>
    <//>`;
}

function Consent() {
  const consent = useResource('/api/enclave/consent');
  const [error, setError] = useState('');
  const c = consent.data.value;
  return html`
    <${Section} title=${t('netmatch.consent_title')}>
      ${
        c &&
        html`
        <blockquote class="ag-quote">${c.statement}</blockquote>
        <p class="rf-ui-help">${t('netmatch.answer_days', {
          days: c.answer_days[c.answer_days.length - 1],
          first: c.answer_days[0],
          second: c.answer_days[1],
        })}</p>
        <${ErrorLine} text=${error} />
        <div class="rf-ui-actions">
          <${ActionButton} label=${t('netmatch.approve')} busyLabel=${t('netmatch.approving')}
            run=${() => call('POST', '/api/enclave/approve', { statement_hash: c.statement_hash })} errorTo=${setError} />
        </div>`
      }
      <${ErrorLine} text=${consent.error.value ? consent.error.value.message : ''} />
    <//>`;
}

function WeeklyCap({ value }) {
  const consent = useResource('/api/enclave/consent');
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

function Answer({ item }) {
  const [card, setCard] = useState({ name: '', institution: '', email: '', lab: '', orcid: '' });
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
  return html`
    ${field('name')}${field('institution')}${field('email')}${field('lab')}${field('orcid')}
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('netmatch.yes')} run=${send('yes')} errorTo=${setError} />
      <${ActionButton} kind="secondary" label=${t('netmatch.not_now')} run=${send('not_now')} errorTo=${setError} />
      <${ActionButton} kind="quiet" label=${t('netmatch.no')} run=${send('no')} errorTo=${setError} />
    </div>`;
}

function Item({ item }) {
  const type = TYPES.includes(item.type) ? t(`netmatch.type_${item.type}`) : item.type;
  if (item.kind === 'reveal') {
    const p = item.card_of_peer;
    return html`
      <${Card} title=${t('netmatch.reveal', { name: p.name })} meta=${type}>
        <${Facts} rows=${[
          [t('netmatch.card_institution'), p.institution],
          [t('netmatch.card_lab'), p.lab],
          [t('netmatch.card_email'), p.email],
          [t('netmatch.card_orcid'), p.orcid],
          [t('netmatch.node'), item.node?.affiliation],
        ]} />
      <//>`;
  }
  if (item.kind === 'proposal') {
    return html`
      <${Card} title=${t('netmatch.proposal', { type })} meta=${t('netmatch.until', { date: fmtTime(item.answer_by) })}>
        <p class="rf-ui-help">${t('netmatch.reasons')}</p>
        <ul>${item.reasons.map((r) => html`<li>${r}</li>`)}</ul>
        ${
          item.choice === 'sent'
            ? html`<p>${t('netmatch.sent')}</p>`
            : html`
            <p>${t('netmatch.choice', { choice: t(`netmatch.${item.choice}`) })}</p>
            ${item.next_checkpoint && html`<p class="rf-ui-help">${t('netmatch.next_checkpoint', { date: fmtDate(String(item.next_checkpoint).slice(0, 10)) })}</p>`}
            <${Answer} item=${item} />`
        }
      <//>`;
  }
  return html`<${Card} title=${t('netmatch.ended')} />`;
}

function View() {
  const state = useResource(STATE, { topics: ['enclave.changed'] });
  const [error, setError] = useState('');
  return html`
    <${Screen} title=${t('netmatch.title')} lead=${t('netmatch.lead')} resources=${[state]}>
      ${() => {
        const s = state.data.value;
        if (!s.set_up) return html`<${Setup} />`;
        return html`
          <p class="rf-ui-help" role="note">${t('netmatch.simulated')}</p>
          <${Lines} draft=${s.draft} />
          ${s.draft && !s.approved && html`<${Consent} />`}
          <${Section} title=${t('netmatch.on_title')}>
            <${Switch} id="nm-on" label=${t('netmatch.on')} checked=${s.on} disabled=${!s.approved && !s.on}
              onChange=${(on) => call('POST', '/api/enclave/on', { on }).catch((e) => setError(e.message))} />
            ${s.approved || s.on ? html`<${WeeklyCap} value=${s.weekly_cap} />` : null}
            <${ErrorLine} text=${error} />
            <div class="rf-ui-actions">
              <${ActionButton} kind="secondary" label=${t('netmatch.run')} busyLabel=${t('netmatch.running')}
                run=${() => call('POST', '/api/enclave/run')} errorTo=${setError} />
            </div>
          <//>
          <${Section} title=${t('netmatch.cards_title')}>
            ${s.cards.length ? s.cards.map((c) => html`<${Item} item=${c} />`) : html`<p>${t('netmatch.no_cards')}</p>`}
          <//>`;
      }}
    <//>`;
}

export const screen = { id: 'netmatch', path: '/network-matching', nav: { group: 'main', order: 45 }, View };
