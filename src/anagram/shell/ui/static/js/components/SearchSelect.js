// Search and choose one result: the brand widget rf.search-select@1.0.0,
// mounted one time from the registry. A parent update does not mount it again.
// The status line of the widget shows only when it adds a fact: not under an
// empty field, and not after a choice (the field shows the choice). The
// "at least 2 characters" hint shows only while the field has 1 character.
import { html, useEffect, useRef } from '../core/html.js';

const WIDGET = { id: 'rf.search-select', version: '1.0.0' };

function quiet(el, state) {
  if (!el) return;
  const short = state.state === 'idle' && state.query.trim().length !== 1;
  el.dataset.quiet = String(short || state.state === 'selected');
}

/**
 * @param {{id: string, label: string, placeholder: string,
 *   search: (query: string, signal: AbortSignal) => Promise<{id, label, detail?}[]>,
 *   onChange: (state: {selected: {id, label}|null, query: string}) => void}} props
 *   `id` has lower-case letters, digits, and '-' only.
 */
export function SearchSelect({ id, label, placeholder, search, onChange }) {
  const host = useRef(null);
  const latest = useRef({ search, onChange });
  latest.current = { search, onChange };
  useEffect(() => {
    const widget = window.RadiofutureWidgets.mount(
      WIDGET,
      host.current,
      { id, version: 1, type: 'search_select', label, placeholder, minQueryLength: 2, value: null },
      (state) => {
        quiet(host.current, state);
        if (latest.current.onChange) latest.current.onChange(state);
      },
      {
        search: async (query, { signal }) => {
          const items = await latest.current.search(query, signal);
          return items
            .slice(0, 20)
            .map((i) => ({ id: i.id, label: i.label, ...(i.detail ? { detail: i.detail } : {}) }));
        },
      },
    );
    return () => widget.destroy();
  }, []);
  return html`<div class="ag-search" data-quiet="true" ref=${host}></div>`;
}
