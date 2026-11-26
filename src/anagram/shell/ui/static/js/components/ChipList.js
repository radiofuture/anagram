// Short items in a row, each with an optional remove control. The remove
// control is a button with a full name ("Remove Maya Lind from
// Collaborators"); what shows is a cross made in CSS, not a character.
import { html } from '../core/html.js';

/**
 * @param {{items: {id: string, label: string}[], label: string,
 *   onRemove?: (item) => void, removeLabel?: (item) => string, empty?: string}} props
 */
export function ChipList({ items, label, onRemove, removeLabel, empty }) {
  if (!items.length) return empty ? html`<p class="rf-ui-help">${empty}</p>` : null;
  return html`
    <ul class="ag-chips" aria-label=${label}>
      ${items.map(
        (item) => html`
        <li class=${`ag-chip${onRemove ? '' : ' ag-chip--plain'}`} key=${item.id}>
          <span>${item.label}</span>
          ${onRemove && html`<${RemoveButton} label=${removeLabel(item)} onClick=${() => onRemove(item)} />`}
        </li>`,
      )}
    </ul>`;
}

/** The remove control: a cross made in CSS, with a full name. */
export function RemoveButton({ label, onClick, large }) {
  return html`
    <button type="button" class=${`ag-x${large ? ' ag-x--large' : ''}`} aria-label=${label} onClick=${onClick}>
      <span class="ag-x-sign" aria-hidden="true"></span>
    </button>`;
}
