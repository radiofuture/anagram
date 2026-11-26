// Sources: what Anagram reads. Track R3 owns this screen (step S15).
//
// With no source, the screen is the choice of the kinds; after that, the
// list comes first and "Add a source" opens the same choice. A row shows
// the label, the kind, and one state ("checked 16 November", "paused", a
// fault). `#/sources/<id>` is the detail of one source: live progress,
// pause and resume, read now, what to include, who can read it, the files
// not read, and remove. Counts are live: a `source.progress` event (the
// source event bridge) moves a row with no reload, and other `source.*`
// events reload the list. No path, token, or ID shows.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { fmtTime } from '../core/format.js';
import { store } from '../core/store.js';
import { absent, mutate, optional, useResource } from '../core/resource.js';
import { href, navigate } from '../core/router.js';
import {
  ActionButton,
  Button,
  Count,
  Disclosure,
  Empty,
  ErrorLine,
  Facts,
  KindLabel,
  Progress,
  Row,
  RowList,
  Screen,
  Settled,
  Section,
  Sheet,
  StatusLine,
  openSheet,
} from '../components/index.js';
import {
  DriveChoice,
  KindGrid,
  MailChoice,
  PagesChoice,
  Setup,
  SignIn,
  SpaceChoice,
  driveKeys,
  named,
  patchSource,
} from '../parts/sources_connect.js';

const MONTHS = [
  'january',
  'february',
  'march',
  'april',
  'may',
  'june',
  'july',
  'august',
  'september',
  'october',
  'november',
  'december',
];
const month = (d) => t(`common.months.${MONTHS[d.getUTCMonth()]}`);

/** '16 November', with the year only when it is not this year. */
function day(iso) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return '';
  const year = d.getUTCFullYear() === new Date().getUTCFullYear() ? '' : ` ${d.getUTCFullYear()}`;
  return `${d.getUTCDate()} ${month(d)}${year}`;
}

/** 'March 2025': how far back a first sync is. */
function monthYear(iso) {
  const d = new Date(iso);
  return !iso || Number.isNaN(d.getTime()) ? '' : `${month(d)} ${d.getUTCFullYear()}`;
}

const hourOf = (iso) => fmtTime(iso).split(', ').pop();

// The counts of a source. The first sync takes the live event first. The
// item counts take the row, which loads again after each source event; a
// live count is used only when it is ahead of the row (the last event of a
// sync comes before the conversion of its items).
function counts(source) {
  const live = store.live.sources.value[source.id] || {};
  const p = source.progress || {};
  const pick = (a, b) => (Number.isFinite(a) ? a : b);
  const ahead = Number.isFinite(live.indexed) && live.indexed > source.indexed;
  return {
    phase: live.phase || source.phase,
    done: pick(live.done, p.done),
    total: pick(live.total, p.total),
    at: live.at || p.at,
    items: source.items,
    indexed: ahead ? live.indexed : source.indexed,
    converting: ahead ? pick(live.converting, source.converting) : source.converting,
  };
}

const isShared = (source) => source.own === false;
const isFirstSync = (source) => source.status === 'first_sync' && !source.paused && !source.fault;

/** The one state of a source, lower case: it follows the kind after a comma. */
function stateWords(source, c) {
  if (isShared(source)) return t('sources.state_shared');
  if (source.paused) return t('sources.state_paused');
  if (source.fault) return t('sources.state_attention');
  if (isFirstSync(source) || c.indexed < c.items) return t('sources.state_reading');
  return source.last_sync_at ? t('sources.state_checked', { date: day(source.last_sync_at) }) : t('sources.state_new');
}

/** The fault sentence, with the time of the next try when there is one. */
function faultText(fault) {
  if (!fault) return '';
  return fault.retry_at ? `${fault.message} ${t('sources.retry_at', { time: hourOf(fault.retry_at) })}` : fault.message;
}

/** Live work of one source: the first sync of a connected source, or the reading of new items. */
function Work({ source }) {
  const c = counts(source);
  if (source.paused || source.fault || isShared(source)) return null;
  // P3: after 30 s with no event, say what the work waits for.
  const waitFor =
    source.account && source.kind_label
      ? t('sources.waiting_for', { name: source.kind_label })
      : t('sources.waiting_files');
  if (isFirstSync(source) && c.phase !== 'live') {
    const label =
      Number.isFinite(c.total) && c.total > 0
        ? html`<${Count} n=${c.done || 0} text=${t('sources.first_sync', { done: c.done || 0, total: c.total })} />`
        : html`<${Count} n=${c.done || 0} text=${t('sources.first_sync_open', { n: c.done || 0 })} />`;
    return html`<${Progress} done=${c.done || 0} total=${Number.isFinite(c.total) && c.total > 0 ? c.total : null}
      waitFor=${waitFor} label=${label} detail=${c.at ? t('sources.now_at', { date: monthYear(c.at) }) : t('sources.newest_first')} />`;
  }
  if (c.indexed < c.items) {
    return html`<${Progress} done=${c.indexed} total=${c.items} waitFor=${waitFor}
      label=${html`<${Count} n=${c.indexed} text=${t('sources.progress', { done: c.indexed, total: c.items })} />`}
      detail=${c.converting ? t('sources.reading', { n: c.converting }) : null} />`;
  }
  return null;
}

const cap = (text) => text.charAt(0).toUpperCase() + text.slice(1);
// A connected source has the kind in its label ("Google Drive (ana@lab.org)").
const kindInLabel = (source) => Boolean(source.kind_label) && String(source.label).startsWith(source.kind_label);

function SourceRow({ source }) {
  const c = counts(source);
  const busy = isFirstSync(source) || c.indexed < c.items;
  const meta = kindInLabel(source)
    ? cap(stateWords(source, c))
    : html`<${KindLabel} kind=${source.kind} label=${source.kind_label} />, ${stateWords(source, c)}`;
  return html`
    <${Row} title=${source.label} href=${href('sources', { id: source.id })}
      meta=${meta}
      action=${html`<${Settled} busy=${busy}>
        <span class="ag-row-fact"><${Count} n=${c.items} text=${t('sources.items', { n: c.items })} /></span>
      <//>`}>
      <${Work} source=${source} />
      ${source.fault && html`<p class=${source.fault.action ? 'rf-ui-error ag-fault' : 'rf-ui-help ag-fault'}>${faultText(source.fault)}</p>`}
    <//>`;
}

// The kinds, and the setup of the one that the person chose.
function AddSource({ kinds }) {
  const [chosen, setChosen] = useState(null);
  const kind = kinds.find((k) => k.kind === chosen);
  const done = () => {
    announce(t('sources.added_one', { kind: kind.label }));
    setChosen(null);
  };
  return html`
    <${KindGrid} kinds=${kinds} chosen=${chosen} onChoose=${setChosen} />
    ${kind && html`<${Setup} key=${kind.kind} kind=${kind} onDone=${done} onCancel=${() => setChosen(null)} />`}`;
}

function List() {
  // The helper sends progress often; the list loads again at most each 2 s.
  const sources = useResource('/api/sources', { topics: ['source'], throttle: 2000 });
  const kinds = useResource('/api/source-kinds', { topics: ['account', 'lab'] });
  const [error, setError] = useState('');
  const [checked, setChecked] = useState('');
  const check = async () => {
    const out = await mutate('POST', '/api/sources/refresh', undefined, { invalidate: ['/api/sources'] });
    setChecked(t('sources.checked', { new: out.new, changed: out.changed }));
  };
  return html`
    <${Screen} title=${t('sources.title')} resources=${[sources]}>
      ${() => {
        const { sources: list, helper } = sources.data.value;
        const all = named((optional(kinds) || { kinds: [] }).kinds);
        if (!list.length) {
          return html`
            <p class="ag-lead">${t('sources.empty')}</p>
            ${all.length ? html`<${AddSource} kinds=${all} />` : html`<${Empty} text=${t('sources.no_kinds')} />`}`;
        }
        return html`
          <${RowList} items=${list} keyOf=${(s) => s.id} label=${t('sources.list')}
            render=${(s) => html`<${SourceRow} source=${s} />`} />
          <div class="ag-sources-foot">
            ${
              helper?.last_cycle_at &&
              html`
              <p class="rf-ui-help">${t('sources.helper', { time: hourOf(helper.last_cycle_at) })}</p>`
            }
            <${ActionButton} kind="quiet" label=${t('sources.check')} busyLabel=${t('sources.check_busy')}
              run=${check} errorTo=${setError} />
          </div>
          <${ErrorLine} text=${error} />
          <${StatusLine} state="saved" text=${checked} />
          ${
            all.length > 0 &&
            html`
            <${Disclosure} kind="add" summary=${t('sources.add')}>
              <${AddSource} kinds=${all} />
            <//>`
          }
          <p class="ag-next"><a href="#/library">${t('sources.next')}</a></p>`;
      }}
    <//>`;
}

// ------------------------------------------------------------------ detail

function Remove({ source }) {
  const [error, setError] = useState('');
  const run = async () => {
    const yes = await openSheet(ConfirmRemove, { label: source.label });
    if (!yes) return;
    const out = await mutate(
      'DELETE',
      `/api/sources/${encodeURIComponent(source.id)}`,
      { delete_data: true },
      { invalidate: ['/api/sources', '/api/drafts', '/api/suggestions', '/api/accounts'] },
    );
    announce(
      out.kept_for_findings
        ? t('sources.removed_kept', { n: out.kept_for_findings })
        : t('sources.removed', { label: source.label }),
    );
    navigate(href('sources'));
  };
  return html`
    <${Section} id="remove-title" title=${t('sources.remove_title')}>
      <p class="rf-ui-help">${t('sources.remove_help')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="danger" label=${t('sources.remove')} busyLabel=${t('sources.removing')} run=${run} errorTo=${setError} />
      </div>
    <//>`;
}

function ConfirmRemove({ label, close }) {
  return html`
    <${Sheet} title=${t('sources.remove_confirm_title')}>
      <p>${t('sources.remove_confirm', { label })}</p>
      <div class="rf-ui-actions">
        <${Button} kind="danger" onClick=${() => close(true)}>${t('sources.remove_confirm_action')}<//>
        <${Button} kind="quiet" onClick=${() => close(false)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

/** The fault of a source: one sentence and one button. */
function Fault({ source, kind, onChoose }) {
  const [error, setError] = useState('');
  const { fault } = source;
  if (!fault) return null;
  const sync = () =>
    mutate('POST', `/api/sources/${encodeURIComponent(source.id)}/sync`, undefined, {
      invalidate: ['/api/sources', `/api/sources/${encodeURIComponent(source.id)}`],
    });
  let action = null;
  if (fault.action === 'signin' && kind && source.account) {
    action = html`<${SignIn} kind=${kind} account=${source.account.id} text="" onAccount=${() => sync().catch(() => null)} />`;
  } else if (fault.action === 'choose' && kind && kind.auth === 'oauth') {
    action = html`<div class="rf-ui-actions"><${Button} kind="secondary" onClick=${onChoose}>${t('sources.choose_again')}<//></div>`;
  } else if (fault.action === 'choose' || fault.action === 'retry') {
    const label = fault.action === 'retry' ? t('sources.try_again') : t('sources.check_again');
    action = html`<div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${label} busyLabel=${t('sources.check_busy')} run=${sync} errorTo=${setError} />
    </div>`;
  }
  return html`
    <div class="ag-source-fault" data-action=${fault.action || 'none'}>
      <p class=${fault.action ? 'rf-ui-error' : 'rf-ui-status'} role=${fault.action ? 'alert' : 'status'}>${faultText(fault)}</p>
      <${ErrorLine} text=${error} />
      ${action}
    </div>`;
}

/** Pause or resume, and read now. */
function Controls({ source }) {
  const [error, setError] = useState('');
  const path = (verb) => `/api/sources/${encodeURIComponent(source.id)}/${verb}`;
  const after = { invalidate: ['/api/sources', `/api/sources/${encodeURIComponent(source.id)}`] };
  return html`
    <div class="ag-source-detail-actions">
    ${source.paused && html`<p class="rf-ui-status">${t('sources.paused_text')}</p>`}
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      ${
        source.paused
          ? html`<${ActionButton} label=${t('sources.resume')} busyLabel=${t('sources.saving')}
            run=${() => mutate('POST', path('resume'), undefined, after)} errorTo=${setError} />`
          : html`
          <${ActionButton} kind="secondary" label=${t('sources.read_now')} busyLabel=${t('sources.check_busy')}
            run=${() => mutate('POST', path('sync'), undefined, after)} errorTo=${setError} />
          <${ActionButton} kind="quiet" label=${t('sources.pause')} busyLabel=${t('sources.saving')}
            run=${() => mutate('POST', path('pause'), undefined, after)} errorTo=${setError} />`
      }
    </div>
    </div>`;
}

/** What a connected source reads; a change reads the new part and deletes what left. */
function Include({ source, kind, open, onOpen }) {
  const [saved, setSaved] = useState('');
  if (kind?.auth !== 'oauth' || !source.account) return null;
  const account = source.account;
  const done = async (body) => {
    await patchSource(source.id, body);
    setSaved(t('sources.include_saved'));
    onOpen(false);
  };
  let body = null;
  if (kind.choose === 'folders') {
    body = html`<${DriveChoice} kind=${kind} account=${account} value=${driveKeys(source.include)}
      action=${t('sources.include_save')} submit=${(include) => done({ include })} />`;
  } else if (kind.choose === 'filter') {
    body = html`<${MailChoice} kind=${kind} account=${account} value=${source.filter}
      action=${t('sources.include_save')} submit=${(filter) => done({ filter })} />`;
  } else if (kind.choose === 'provider') {
    body = html`<${PagesChoice} kind=${kind} account=${account} />`;
  }
  if (!body) return null;
  const always = kind.choose === 'provider';
  return html`
    <${Section} id="include-title" title=${t('sources.include_title')}>
      <${StatusLine} state="saved" text=${saved} />
      ${
        always || open
          ? body
          : html`<div class="rf-ui-actions"><${Button} kind="secondary" onClick=${() => {
              setSaved('');
              onOpen(true);
            }}>
            ${t('sources.include_change')}<//></div>`
      }
    <//>`;
}

/** Who can read a source: only you, or a lab. */
function Space({ source, kind }) {
  const [error, setError] = useState('');
  if (!kind?.labs?.length) return null;
  const change = async (space) => {
    setError('');
    try {
      await patchSource(source.id, { space });
    } catch (err) {
      setError(err.message);
    }
  };
  return html`
    <${Section} id="space-title" title=${t('sources.space')}>
      <${SpaceChoice} kind=${kind} value=${source.space} onChange=${change} name="detail-space" hideLegend />
      <${ErrorLine} text=${error} />
    <//>`;
}

function Skipped({ source }) {
  if (!source.skipped_count) return null;
  return html`
    <${Disclosure} kind="details" summary=${t('sources.skipped', { n: source.skipped_count })}>
      <ul class="ag-plain" aria-label=${t('sources.skipped_list')}>
        ${source.skipped.map(
          (k) => html`
          <li key=${k.key}>
            <span>${k.name || t('sources.skipped_item')}: ${k.reason}</span>
            ${k.fix && html`<small class="rf-ui-help">${k.fix}</small>`}
          </li>`,
        )}
      </ul>
    <//>`;
}

function spaceName(source, kinds) {
  if (!source.space || source.space === 'private') return t('sources.space_private');
  for (const k of kinds) {
    const lab = (k.labs || []).find((l) => l.space === source.space);
    if (lab) return lab.name;
  }
  return t('sources.space_lab');
}

function Detail({ id }) {
  const path = `/api/sources/${encodeURIComponent(id)}`;
  const source = useResource(path, { topics: ['source'], throttle: 1000 });
  const kinds = useResource('/api/source-kinds', { topics: ['account', 'lab'] });
  const [choosing, setChoosing] = useState(false);
  const missing = absent(source);
  const data = source.data.value;
  const back = { href: href('sources'), label: t('sources.back') };
  return html`
    <${Screen} title=${data ? data.label : t('sources.title')} back=${back} resources=${missing ? [] : [source]}>
      ${() => {
        if (missing || !data) return html`<${Empty} text=${t('sources.gone')} action=${back} />`;
        const all = named((optional(kinds) || { kinds: [] }).kinds);
        const kind = all.find((k) => k.kind === data.kind);
        const c = counts(data);
        const choice = Boolean(kind?.labs?.length) && !isShared(data);
        const facts = html`<${Facts} rows=${[
          [
            t('sources.fact_kind'),
            !kindInLabel(data) && html`<${KindLabel} kind=${data.kind} label=${data.kind_label} />`,
          ],
          [t('sources.fact_account'), data.account?.label],
          [t('sources.space'), !choice && spaceName(data, all)],
          [t('sources.fact_items'), String(c.items)],
          [t('sources.fact_checked'), data.last_sync_at && day(data.last_sync_at)],
        ]} />`;
        if (isShared(data)) {
          return html`${facts}<p class="rf-ui-help">${t('sources.lab_source')}</p>`;
        }
        return html`
          ${facts}
          <${Work} source=${data} />
          <${Fault} source=${data} kind=${kind} onChoose=${() => setChoosing(true)} />
          ${!data.fault && html`<${Controls} source=${data} />`}
          <${Space} source=${data} kind=${kind} />
          <${Include} source=${data} kind=${kind} open=${choosing} onOpen=${setChoosing} />
          <${Skipped} source=${data} />
          <${Remove} source=${data} />`;
      }}
    <//>`;
}

function View({ params }) {
  return params?.id ? html`<${Detail} key=${params.id} id=${params.id} />` : html`<${List} />`;
}

export const screen = { id: 'sources', path: '/sources/:id?', nav: { group: 'main', order: 60 }, View };
