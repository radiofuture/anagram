// A flat record card (brand class rf-record-card). For a small number of rich
// records only. A long list uses RowList.
import { html } from '../core/html.js';

export function Card({ title, meta, level = 3, children }) {
  const Tag = `h${level}`;
  return html`
    <article class="rf-record-card ag-card">
      <${Tag} class="ag-card-title">${title}<//>
      ${meta && html`<p class="rf-ui-help">${meta}</p>`}
      ${children}
    </article>`;
}

/** Term and value rows. A row with no value does not show: never `null`. */
export function Facts({ rows }) {
  const shown = rows.filter(
    (row) => row && row[1] !== null && row[1] !== undefined && row[1] !== '' && row[1] !== false,
  );
  if (!shown.length) return null;
  return html`
    <dl class="ag-facts">
      ${shown.map(([term, value]) => html`<div key=${term}><dt>${term}</dt><dd>${value}</dd></div>`)}
    </dl>`;
}
