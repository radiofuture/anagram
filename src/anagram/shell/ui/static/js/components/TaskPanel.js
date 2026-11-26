// The one offset panel: paper, an ink edge, and the hard blue offset. A
// screen has at most one (brand FOUNDATIONS: "one opaque panel with one blue
// offset for the main task"). A second panel on the screen is reported.
import { html, useEffect } from '../core/html.js';

export function TaskPanel({ label, children }) {
  useEffect(() => {
    if (document.querySelectorAll('main .ag-proof').length > 1) {
      console.error('TaskPanel: a screen has at most one offset panel.');
    }
  }, []);
  return html`<section class="ag-proof" aria-label=${label}>${children}</section>`;
}
