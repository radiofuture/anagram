(function () {
  'use strict';
  const S = RadiofutureWidgetSupport;
  function item(value) {
    S.object(value, ['id', 'label', 'detail']); S.text(value.id, 80); S.text(value.label, 120);
    if (value.detail !== undefined) S.text(value.detail, 240);
    return Object.freeze({ ...value });
  }
  function validate(data) {
    S.identity(data, 'search_select', ['label', 'placeholder', 'minQueryLength', 'value']); S.text(data.label, 180); S.text(data.placeholder, 120);
    if (!Number.isInteger(data.minQueryLength) || data.minQueryLength < 1 || data.minQueryLength > 10) throw new Error('Invalid query threshold.');
    return Object.freeze({ ...data, value: data.value === null ? null : item(data.value) });
  }
  function mount(parent, definition, onChange, options) {
    if (typeof options.search !== 'function') throw new Error('Search requires a host adapter.');
    const scope = S.scope(); const id = S.uid();
    const root = S.el('div', 'rf-ui-search');
    const label = S.el('label', 'rf-ui-field', definition.label);
    const input = S.el('input', 'rf-ui-input'); input.type = 'search'; input.maxLength = 120; input.placeholder = definition.placeholder;
    input.id = `${id}-query`; label.htmlFor = input.id; label.append(input);
    const status = S.el('p', 'rf-ui-help'); status.id = `${id}-status`; status.setAttribute('role', 'status'); input.setAttribute('aria-describedby', status.id);
    const results = S.el('fieldset', 'rf-ui-search-results'); results.hidden = true;
    const legend = S.el('legend', 'rf-ui-sr-only', 'Search results'); results.append(legend);
    const list = S.el('div', 'rf-ui-answer-list'); results.append(list);
    const retry = S.el('button', 'rf-ui-button rf-ui-button--secondary', 'Try again'); retry.type = 'button'; retry.hidden = true;
    root.append(label, status, results, retry); parent.append(root);
    let currentResults = new Map();
    let selected = definition.value, state = selected ? 'selected' : 'idle', generation = 0, timer, request, destroyed = false;
    input.value = selected?.label ?? '';
    status.textContent = selected ? `Selected: ${selected.label}` : `Enter at least ${definition.minQueryLength} characters.`;
    const read = () => ({ query: input.value, selected, state, valid: selected !== null });
    function cancel() { generation += 1; clearTimeout(timer); request?.abort(); }
    async function search() {
      cancel(); const ticket = generation; const query = input.value.trim();
      selected = null; list.replaceChildren(); results.hidden = true; retry.hidden = true;
      if (query.length < definition.minQueryLength) { state = 'idle'; status.textContent = `Enter at least ${definition.minQueryLength} characters.`; onChange(read()); return; }
      state = 'working'; status.textContent = 'Finding matches…'; onChange(read());
      request = new AbortController();
      try {
        const response = await options.search(query, { signal: request.signal });
        if (destroyed || ticket !== generation) return;
        if (!Array.isArray(response) || response.length > 20) throw new Error('Invalid search response.');
        const items = response.map(item);
        currentResults = new Map(items.map(value => [value.id, value]));
        if (new Set(items.map(value => value.id)).size !== items.length) throw new Error('Duplicate result.');
        state = items.length ? 'ready' : 'empty'; status.textContent = items.length ? `${items.length} ${items.length === 1 ? 'match' : 'matches'}. Choose one.` : 'No matches. Try a different name or area.';
        for (const result of items) {
          const row = S.el('label', 'rf-ui-search-result');
          const radio = S.el('input'); radio.type = 'radio'; radio.name = id; radio.value = result.id;
          const copy = S.el('span', '', result.label); if (result.detail) copy.append(S.el('small', 'rf-ui-help', result.detail));
          row.append(radio, copy); list.append(row);
        }
        results.hidden = items.length === 0; onChange(read());
      } catch (error) {
        if (destroyed || ticket !== generation) return;
        state = 'failed'; status.textContent = 'Could not load matches. Your search is kept.'; retry.hidden = false; onChange(read());
      }
    }
    scope.listen(list, 'change', event => {
      const result = currentResults.get(event.target.value);
      if (!result) return;
      selected = result; state = 'selected'; status.textContent = `Selected: ${result.label}`; onChange(read());
    });
    scope.listen(input, 'input', () => {
      cancel(); selected = null; state = 'idle'; list.replaceChildren(); results.hidden = true; retry.hidden = true;
      status.textContent = input.value.trim().length < definition.minQueryLength ? `Enter at least ${definition.minQueryLength} characters.` : 'Ready to search…';
      onChange(read()); timer = setTimeout(search, 180);
    });
    scope.listen(retry, 'click', search);
    return Object.freeze({ definition, read, focus: () => input.focus(), retry: search, destroy: () => { destroyed = true; cancel(); scope.destroy(); root.remove(); } });
  }
  RadiofutureWidgets.register({ id: 'rf.search-select', version: '1.0.0', name: 'Search and choose', description: 'Search a host-provided list and choose one result.', definitionSchema: 'search-selection-v1', status: 'reference', entry: 'search-select/widget.js', docs: 'search-select/README.md', example: '../planning.html' }, { validate, mount });
})();
