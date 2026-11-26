// One format for each object in the whole product: a date, a person, a kind.
import { html } from '../core/html.js';
import { has, t } from '../core/copy.js';
import { fmtDate, fmtTime } from '../core/format.js';

/** '16 November 2026'. With `time`, the hour and minute follow. */
export function DateText({ iso, time = false }) {
  if (!iso) return null;
  return html`<time datetime=${iso}>${time ? fmtTime(iso) : fmtDate(iso)}</time>`;
}

/** A person: the name, then the lab and the institution in one quieter line. */
export function PersonLine({ person }) {
  const where = [person.lab, person.institution].filter(Boolean).join(', ');
  return html`
    <span class="ag-person">
      <span class="ag-person-name">${person.name || person.label}</span>
      ${where && html`<small class="rf-ui-help">${where}</small>`}
    </span>`;
}

/** The kind of a thing in the words of the product. `label` is the text of the API, used when the copy has no word. */
export function KindLabel({ kind, label }) {
  const key = `common.kinds.${kind}`;
  return has(key) ? t(key) : label || kind || '';
}
