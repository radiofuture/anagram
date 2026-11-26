// The words of one share: the state of a person, and the facts after it.
// The finding screen (slot `finding.sections`), the sharing screen, and the
// history of one person use them, so a state reads the same in each place.
// Track R5 owns this file.
import { html, useRef } from '../core/html.js';
import { t } from '../core/copy.js';
import { fmtDate } from '../core/format.js';

/** The state word of a history row (plan R5 section 8.4). */
export function stateKey(row) {
  if (row.state === 'stopped') return 'stopped';
  if (row.person.kind === 'lab') return 'lab';
  if (row.person.kind === 'invite') return 'invited';
  return row.state; // waiting, delivered, read
}

function lastEvent(row, kind) {
  const found = row.events.filter((e) => e.kind === kind);
  return found.length ? found[found.length - 1].at : null;
}

/** The facts after the state: when, and how many times it was opened. */
export function stateFacts(row) {
  switch (stateKey(row)) {
    case 'read':
      return t('sharing.fact_reads', { n: row.reads, date: fmtDate(row.last_read_at) });
    case 'waiting':
      return t('sharing.fact_waiting');
    case 'invited':
      return t('sharing.fact_invited', { date: fmtDate(row.shared_at) });
    case 'lab':
      return t('sharing.fact_lab');
    case 'stopped':
      return t('sharing.fact_stopped', { date: fmtDate(lastEvent(row, 'stopped') || row.shared_at) });
    default:
      return t('sharing.fact_shared', { date: fmtDate(row.shared_at) });
  }
}

/**
 * The state word. A change from a live event replaces the old word with an
 * opacity change (motion recipe S1); the first word has no motion. With
 * reduced motion the change is immediate (css/motion.css).
 */
export function StateWord({ row }) {
  const key = stateKey(row);
  const before = useRef(null);
  const swap = before.current !== null && before.current !== key;
  before.current = key;
  return html`
    <span class="ag-share-state" data-state=${key}>
      <span key=${key} class=${swap ? 'ag-m-swap' : undefined}>${t(`sharing.state_${key}`)}</span>
    </span>`;
}

/** The state word and its facts, for the meta line of a row. */
export function StateLine({ row }) {
  return html`<${StateWord} row=${row} /><span class="ag-share-facts">, ${stateFacts(row)}</span>`;
}

/** A name for the screen: never an id. */
export function personName(row) {
  return row.person.label || t('sharing.a_member');
}
