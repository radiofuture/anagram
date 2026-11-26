// Compact rows for lists. A long list is rows, not a stack of equal cards.
//
// Row: a title, an optional line of facts, an optional second line, and at
// most one action at the end. With `href` the title area is the link.
// RowList: keyed rows. A row that arrives after the first paint opens from
// height 0 and has a lime edge (motion recipe L1). The edge goes when the
// person moves focus or the pointer onto the row. The first paint has no
// motion (L2). A row that goes fades, then closes to height 0 (L3); if the
// focus was in it, the focus goes to the next row.
import { html, useEffect, useLayoutEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { leaveRow, openHeight } from '../core/motion.js';

export function Row({ id, title, meta, note, href, action, fresh, children }) {
  const main = html`
    <span class="ag-row-title">${title}</span>
    ${meta && html`<span class="ag-row-meta">${meta}</span>`}
    ${note && html`<span class="ag-row-note">${note}</span>`}`;
  return html`
    <div class="ag-row" data-fresh=${fresh ? 'true' : undefined}>
      ${
        href
          ? html`<a class="ag-row-main ag-row-link" id=${id} href=${href}>${main}</a>`
          : html`<div class="ag-row-main" id=${id}>${main}</div>`
      }
      ${action && html`<div class="ag-row-action">${action}</div>`}
      ${children && html`<div class="ag-row-more">${children}</div>`}
    </div>`;
}

function Item({ fresh, leaving, onSeen, onGone, children }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (fresh && ref.current) openHeight(ref.current);
  }, []);
  // L3: the same element stays while it goes, so that the focus in it can
  // move to the next row first.
  useLayoutEffect(() => {
    const li = ref.current;
    if (!leaving || !li) return;
    if (li.contains(document.activeElement)) focusAfter(li);
    li.inert = true;
    leaveRow(li).then(onGone);
  }, [leaving]);
  // Leaving the screen also ends the mark.
  useEffect(
    () => () => {
      if (fresh) onSeen();
    },
    [],
  );
  return html`
    <li class="ag-rows-item" ref=${ref} data-fresh=${fresh && !leaving ? 'true' : undefined}
      data-leaving=${leaving ? 'true' : undefined} aria-hidden=${leaving ? 'true' : undefined}
      onPointerEnter=${fresh ? onSeen : undefined} onFocusIn=${fresh ? onSeen : undefined}>
      ${children}
    </li>`;
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** The first control of the next row, else of the row before, else the list. */
function focusAfter(li) {
  for (let at = li.nextElementSibling; at; at = at.nextElementSibling) {
    const el = at.dataset.leaving ? null : at.querySelector(FOCUSABLE);
    if (el) return el.focus();
  }
  for (let at = li.previousElementSibling; at; at = at.previousElementSibling) {
    const el = at.dataset.leaving ? null : at.querySelector(FOCUSABLE);
    if (el) return el.focus();
  }
  const list = li.parentElement;
  if (list) {
    list.setAttribute('tabindex', '-1');
    list.focus();
  }
  return undefined;
}

/**
 * @param {{items: object[]|null, keyOf: (item) => string, render: (item, state) => any,
 *   label: string, empty?: any, ordered?: boolean}} props
 *   `items` is null while the first load runs. `render` gets `{ fresh }`.
 */
export function RowList({ items, keyOf, render, label, empty, ordered }) {
  const seen = useRef(null);
  const last = useRef([]); // [{ key, item }] of the last render
  const gone = useRef(new Map()); // key -> { item, after }: rows that go (L3)
  const [, setTick] = useState(0);
  const [fresh, setFresh] = useState(() => new Set());
  const keys = items ? items.map(keyOf) : null;
  // L3: a row that went keeps its element and its place until its motion
  // ends. This is found in the render, so that the element is not replaced.
  if (keys && seen.current !== null) {
    const now = new Set(keys);
    last.current.forEach((row, i) => {
      if (!now.has(row.key) && !gone.current.has(row.key)) {
        gone.current.set(row.key, { item: row.item, after: i ? last.current[i - 1].key : null });
      }
    });
    for (const k of [...gone.current.keys()]) if (now.has(k)) gone.current.delete(k);
  }
  if (keys) last.current = items.map((item, i) => ({ key: keys[i], item }));
  useLayoutEffect(() => {
    if (!keys) return;
    if (seen.current === null) {
      seen.current = new Set(keys); // the first paint: no row is new
      return;
    }
    const added = keys.filter((k) => !seen.current.has(k));
    if (!added.length) return;
    for (const k of added) seen.current.add(k);
    setFresh((old) => new Set([...old, ...added]));
    announce(t('common.new_rows', { n: added.length, list: label }), { gap: 5000 });
  }, [keys ? keys.join('\n') : null]);
  if (!items) return null;
  if (!items.length && !gone.current.size) return empty || null;
  const seenRow = (key) => () =>
    setFresh((old) => {
      if (!old.has(key)) return old;
      const next = new Set(old);
      next.delete(key);
      return next;
    });
  const goneRow = (key) => () => {
    if (gone.current.delete(key)) setTick((n) => n + 1);
  };
  // The rows of now, with each row that goes after the row that was before it.
  const rows = items.map((item, i) => ({ key: keys[i], item, leaving: false }));
  for (const [key, g] of gone.current) {
    const at = g.after === null ? -1 : rows.findIndex((r) => r.key === g.after);
    rows.splice(g.after === null ? 0 : at < 0 ? rows.length : at + 1, 0, { key, item: g.item, leaving: true });
  }
  const Tag = ordered ? 'ol' : 'ul';
  return html`
    <${Tag} class="ag-rows" aria-label=${label}>
      ${rows.map(({ key, item, leaving }) => {
        // A row is new from its first render, before the effect above runs.
        const isNew = !leaving && (fresh.has(key) || (seen.current !== null && !seen.current.has(key)));
        return html`
          <${Item} key=${key} fresh=${isNew} leaving=${leaving} onSeen=${seenRow(key)} onGone=${goneRow(key)}>
            ${render(item, { fresh: isNew })}
          <//>`;
      })}
    <//>`;
}
