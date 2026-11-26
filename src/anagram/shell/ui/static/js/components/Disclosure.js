// Optional reference material: a native <details>. The content opens from
// height 0 (motion recipe D1). The open state belongs to the element, so a
// data update does not close it.
// `kind`: 'more' (a ruled block), 'details' (small, for ids and places),
// 'add' (reads as a link; for a small form).
import { html, useLayoutEffect, useRef } from '../core/html.js';
import { closeHeight, openHeight } from '../core/motion.js';

export function Disclosure({ summary, children, open = false, kind = 'more', onToggle }) {
  const ref = useRef(null);
  const body = useRef(null);
  useLayoutEffect(() => {
    if (open && ref.current) ref.current.open = true;
  }, []);
  const click = async (e) => {
    e.preventDefault();
    const el = ref.current;
    if (el.open) {
      await closeHeight(body.current);
      el.open = false;
    } else {
      el.open = true;
      openHeight(body.current);
    }
    if (onToggle) onToggle(el.open);
  };
  return html`
    <details class=${`ag-disclosure ag-disclosure--${kind}`} ref=${ref}>
      <summary onClick=${click}><span class="ag-disclosure-sign" aria-hidden="true"></span><span>${summary}</span></summary>
      <div class="ag-disclosure-body" ref=${body}>${children}</div>
    </details>`;
}
