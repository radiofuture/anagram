// A part of a screen with its own heading. `count` is an optional short fact
// at the end of the heading line (for example "12 items").
import { html } from '../core/html.js';

export function Section({ title, id, count, children }) {
  return html`
    <section aria-labelledby=${id}>
      <div class="ag-section-head">
        <h2 class="ag-section" id=${id}>${title}</h2>
        ${count && html`<p class="ag-section-count">${count}</p>`}
      </div>
      ${children}
    </section>`;
}
