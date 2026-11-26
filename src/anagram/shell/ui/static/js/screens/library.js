// Library: what Anagram found in your sources. Today it holds the findings:
// proposals (drafts) and the findings that you timestamped. New proposals
// come first, then the timestamped findings, then the proposals that you saw
// before. When the item routes of track R4 exist (`/api/kinds`,
// `/api/items`), the kinds show above the list and each kind is one route.
import { html, useEffect } from '../core/html.js';
import { t, tx } from '../core/copy.js';
import { baseName, cleanText, fmtDate, fmtRange } from '../core/format.js';
import { optional, useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { Empty, Row, RowList, Screen, Section } from '../components/index.js';

const FINDINGS = 'findings';

export function provenLine(version) {
  return version.proven_by ? t('library.proven', { date: fmtDate(version.proven_by) }) : t('library.waiting');
}

export function sharedLine(version) {
  return version.shared_with.length
    ? t('library.shared_with', { who: version.shared_with.join(', ') })
    : t('library.not_shared');
}

// Decision C12: a negative result (a null or negative outcome) shows one
// quiet word in the facts line. It is still a finding: proof and share.
export function polarityWord(x) {
  return x && x.polarity === 'negative' ? t('library.negative') : null;
}

export function findingTitle(f) {
  return f.claim || f.evidence.map((e) => e.name).join(', ') || t('library.no_claim');
}

// ------------------------------------------------------------ new or seen

// A proposal is new when this computer did not show it before this page
// load. The record is a convenience of this browser only: without it, each
// proposal is new.
const SEEN_KEY = 'anagram.seen.proposals';
let before = null; // the ids seen before this page load (fixed for the page)

function readSeen() {
  try {
    const raw = window.localStorage.getItem(SEEN_KEY);
    const list = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(list) ? list : []);
  } catch {
    return new Set();
  }
}

function seenBefore() {
  if (before === null) before = readSeen();
  return before;
}

function remember(ids) {
  try {
    const all = new Set([...readSeen(), ...ids]);
    window.localStorage.setItem(SEEN_KEY, JSON.stringify([...all].slice(-500)));
  } catch {
    // Private window or blocked storage: each proposal stays new.
  }
}

const isNew = (d) => d.state !== 'later' && !seenBefore().has(d.id);

// The newest work first; with the same date, the larger group first. A
// proposal that the person put off ("Later") goes to the end.
const order = (a, b) =>
  (a.state === 'later') - (b.state === 'later') ||
  String(b.end || '').localeCompare(String(a.end || '')) ||
  b.items.length - a.items.length;

// ------------------------------------------------------------ rows

function DraftRow({ draft }) {
  const claim = cleanText(draft.claim_suggestion);
  const meta = [
    polarityWord(draft),
    claim ? draft.title : null,
    fmtRange(draft.start, draft.end),
    t('library.items', { n: draft.items.length }),
    draft.third_party ? t('library.third_party') : null,
  ]
    .filter(Boolean)
    .join(', ');
  return html`<${Row} id=${`draft-${draft.id}`} title=${claim || draft.title} meta=${meta}
    note=${cleanText(draft.reason) || null} href=${href('draft', { id: draft.id })} />`;
}

function FindingRow({ finding }) {
  const v = finding.versions[0];
  const meta = [
    polarityWord(finding),
    provenLine(v),
    v.version > 1 ? t('library.version', { n: v.version }) : null,
    sharedLine(v),
  ]
    .filter(Boolean)
    .join(', ');
  return html`<${Row} id=${`finding-${finding.root}`} title=${findingTitle(finding)} meta=${meta}
    href=${href('finding', { root: finding.root })} />`;
}

// A summary that starts with the title says nothing more.
export function extraText(title, text) {
  const a = cleanText(title)
    .toLowerCase()
    .replace(/[.:]+$/, '');
  const b = cleanText(text);
  return b && !b.toLowerCase().startsWith(a) ? b : null;
}

function ItemRow({ item }) {
  const meta = [polarityWord(item), baseName(item.source_label), item.time ? fmtDate(item.time) : null]
    .filter(Boolean)
    .join(', ');
  return html`<${Row} id=${`item-${item.ref}`} title=${cleanText(item.title) || t('library.untitled')} meta=${meta}
    note=${extraText(item.title, item.summary)} href=${href('item', { id: item.ref })} />`;
}

// ------------------------------------------------------------ kinds

function kindList(data) {
  const list = Array.isArray(data) ? data : data?.kinds || [];
  return list
    .map((k) => ({ ...k, kind: k.kind || k.id }))
    .filter((k) => k.kind && k.kind !== FINDINGS && !(Number.isFinite(k.count) && k.count === 0));
}

function Kinds({ kinds, current }) {
  if (!kinds.length) return null;
  const all = [{ kind: FINDINGS, label: t('library.kind_findings') }, ...kinds];
  return html`
    <nav class="ag-tabs" aria-label=${t('library.kinds')}>
      <ul>
        ${all.map(
          (k) => html`
          <li key=${k.kind}>
            <a href=${href('library', { kind: k.kind === FINDINGS ? undefined : k.kind })}
              aria-current=${current === k.kind ? 'page' : undefined}>
              ${k.label}${Number.isFinite(k.count) ? html` <span class="ag-tab-count">${k.count}</span>` : null}
            </a>
          </li>`,
        )}
      </ul>
    </nav>`;
}

function ItemsOfKind({ kind, label }) {
  const items = useResource(`/api/items?kind=${encodeURIComponent(kind)}&limit=50`, {
    topics: ['item', 'source.progress'],
    throttle: 2000,
  });
  const data = optional(items);
  const list = data ? (Array.isArray(data) ? data : data.items || []) : [];
  return html`
    <${RowList} items=${data ? list : null} keyOf=${(i) => i.ref} label=${label}
      render=${(i) => html`<${ItemRow} item=${i} />`}
      empty=${html`<${Empty} text=${t('library.kind_empty')} action=${{ href: href('sources'), label: t('library.connect') }} />`} />`;
}

// ------------------------------------------------------------ findings

function Findings({ drafts, findings }) {
  const sorted = [...drafts].sort(order);
  const fresh = sorted.filter(isNew);
  const older = sorted.filter((d) => !isNew(d));
  // The proposals on the screen count as seen at the next page load.
  useEffect(() => () => remember(drafts.map((d) => d.id)), [drafts.map((d) => d.id).join(' ')]);
  if (!drafts.length && !findings.length) {
    return html`<${Empty} text=${t('library.empty')} action=${{ href: href('sources'), label: t('library.connect') }} />`;
  }
  const proposals = (id, title, list) => html`
    <${Section} id=${id} title=${title} count=${list.length ? t('library.proposals_n', { n: list.length }) : null}>
      <${RowList} items=${list} keyOf=${(d) => d.id} label=${title}
        render=${(d) => html`<${DraftRow} draft=${d} />`} />
    <//>`;
  return html`
    ${fresh.length > 0 && proposals('new-title', t('library.new_title'), fresh)}
    <${Section} id="stamped-title" title=${t('library.stamped_title')}
      count=${findings.length ? t('library.findings_n', { n: findings.length }) : null}>
      <${RowList} items=${findings} keyOf=${(f) => f.root} label=${t('library.stamped_title')}
        render=${(f) => html`<${FindingRow} finding=${f} />`}
        empty=${html`<${Empty} text=${t(drafts.length ? 'library.stamped_empty' : 'library.stamped_none')} />`} />
    <//>
    ${older.length > 0 && proposals('proposals-title', t('library.proposals_title'), older)}
    ${
      !drafts.length &&
      html`
      <p class="ag-empty">${tx('library.drafts_empty', { link: html`<a href=${href('sources')}>${t('library.drafts_empty_link')}</a>` })}</p>`
    }`;
}

function View({ params }) {
  const drafts = useResource('/api/suggestions', { topics: ['draft.changed', 'suggestion'] });
  const findings = useResource('/api/findings', { topics: ['finding.changed'] });
  const kindsRes = useResource('/api/kinds', { topics: ['item'], throttle: 2000 });
  const kinds = kindList(optional(kindsRes));
  const current = params.kind && kinds.some((k) => k.kind === params.kind) ? params.kind : FINDINGS;
  const label = current === FINDINGS ? null : kinds.find((k) => k.kind === current)?.label;
  return html`
    <${Screen} title=${t('library.title')} resources=${[drafts, findings]}>
      ${() => html`
        <${Kinds} kinds=${kinds} current=${current} />
        ${
          current === FINDINGS
            ? html`<${Findings} drafts=${drafts.data.value} findings=${findings.data.value} />`
            : html`<${ItemsOfKind} key=${current} kind=${current} label=${label} />`
        }`}
    <//>`;
}

export const screen = { id: 'library', path: '/library/:kind?', nav: { group: 'main', order: 20 }, View };
