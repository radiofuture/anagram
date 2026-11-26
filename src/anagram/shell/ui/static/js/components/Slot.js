// Renders the views that other modules gave to a slot (core/slots.js).
// With no view, it renders nothing.
import { html } from '../core/html.js';
import { provided } from '../core/slots.js';

export function Slot({ name, props = {} }) {
  return provided(name)
    .filter((entry) => typeof entry.View === 'function')
    .map((entry, i) => html`<${entry.View} key=${i} ...${props} />`);
}
