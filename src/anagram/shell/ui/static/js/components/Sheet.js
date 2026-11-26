// The one sheet of the product: a native <dialog class="rf-ui-sheet">. It has
// native modal focus and dismissal, and no custom entrance (MOTION.md). Focus
// returns to the control that opened it.
//
//   const answer = await openSheet(ConfirmView, { names });
//   function ConfirmView({ names, close }) { … close(true) … }
import { html, useLayoutEffect, useRef } from '../core/html.js';
import { store } from '../core/store.js';

/** Open the sheet with a view. The promise gives the value of `close(value)`; undefined after Escape. */
export function openSheet(View, props = {}) {
  return new Promise((resolve) => {
    const before = store.dialog.peek();
    if (before) before.resolve(undefined);
    store.dialog.value = { View, props, resolve, opener: document.activeElement };
  });
}

function closeSheet(value) {
  const open = store.dialog.peek();
  if (!open) return;
  store.dialog.value = null;
  open.resolve(value);
  if (open.opener?.isConnected && typeof open.opener.focus === 'function') open.opener.focus();
}

export function SheetHost() {
  const open = store.dialog.value;
  const ref = useRef(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);
  const View = open ? open.View : null;
  return html`
    <dialog class="rf-ui-sheet ag-sheet" ref=${ref} aria-labelledby="sheet-title"
      onCancel=${(e) => {
        e.preventDefault();
        closeSheet(undefined);
      }}
      onClose=${() => closeSheet(undefined)}>
      ${View && html`<${View} ...${open.props} close=${closeSheet} />`}
    </dialog>`;
}

/** The content of a sheet: a title and the task. */
export function Sheet({ title, children }) {
  return html`
    <h2 id="sheet-title" tabindex="-1">${title}</h2>
    ${children}`;
}
