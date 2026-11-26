// Text near the task: an error, a status, an empty state. Each renders
// nothing when it has no text.
import { html, useRef } from '../core/html.js';

/** What happened and one next step. `role="alert"`. */
export function ErrorLine({ text }) {
  if (!text) return null;
  return html`<p class="rf-ui-error" role="alert">${text}</p>`;
}

/**
 * The state of the task, in place. `state`: 'pending', 'saved', 'error',
 * 'outdated', or a state of the screen. A new text replaces the old text
 * with an opacity change (motion recipe S1); the first text has no motion.
 */
export function StatusLine({ state = 'saved', text, id }) {
  const before = useRef(null);
  if (!text) {
    before.current = null;
    return null;
  }
  const swap = before.current !== null && before.current !== text;
  before.current = text;
  return html`
    <p class="rf-ui-status ag-status" role="status" id=${id} data-state=${state}>
      <span key=${text} class=${swap ? 'ag-m-swap' : undefined}>${text}</span>
    </p>`;
}

/** What is missing and one next action: `{ label, href }` or `{ label, onClick }`. */
export function Empty({ text, action, children }) {
  return html`
    <div class="ag-empty">
      <p>${text || children}</p>
      ${
        action &&
        (action.href
          ? html`<p><a href=${action.href}>${action.label}</a></p>`
          : html`<p><button type="button" class="ag-link" onClick=${action.onClick}>${action.label}</button></p>`)
      }
    </div>`;
}
