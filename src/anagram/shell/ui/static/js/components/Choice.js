// Choices on native controls. Selection shows as the lime fill, the ink
// border, and the native control (review W4: no second mark).
import { html } from '../core/html.js';

/** One choice from a few: native radios in brand choice cards. */
export function ChoiceGroup({ legend, name, value, options, onChange, hideLegend }) {
  return html`
    <fieldset class="rf-ui-choices ag-choices">
      <legend class=${hideLegend ? 'rf-ui-sr-only' : undefined}>${legend}</legend>
      ${options.map((o) => {
        const id = `${name}-${o.value}`;
        return html`
          <label class="rf-ui-choice-card" for=${id} key=${o.value}>
            <input type="radio" name=${name} id=${id} value=${o.value} checked=${o.value === value}
              onChange=${() => onChange(o.value)} />
            <span>${o.label}${o.help && html`<small>${o.help}</small>`}</span>
          </label>`;
      })}
    </fieldset>`;
}

/**
 * Several choices: native checkboxes. `value` is the list of chosen values.
 * An item with `fixed: true` shows as a row with no control.
 */
export function CheckList({ legend, name, items, value, onChange }) {
  const chosen = new Set(value);
  const toggle = (v) => {
    const next = new Set(chosen);
    if (next.has(v)) next.delete(v);
    else next.add(v);
    onChange(items.map((i) => i.value).filter((x) => next.has(x)));
  };
  return html`
    <fieldset class="rf-ui-choices ag-checks">
      <legend>${legend}</legend>
      ${items.map((item, n) => {
        const id = `${name}-${n}`;
        const text = html`<span>${item.label}${item.help && html`<small class="rf-ui-help">${item.help}</small>`}</span>`;
        if (item.fixed) return html`<p class="ag-check ag-check--fixed" key=${item.value}>${text}</p>`;
        return html`
          <label class="ag-check" for=${id} key=${item.value}>
            <input type="checkbox" id=${id} value=${item.value} checked=${chosen.has(item.value)}
              onChange=${() => toggle(item.value)} />
            ${text}
          </label>`;
      })}
    </fieldset>`;
}

/** A named setting that is on or off and takes effect at once. */
export function Switch({ id, label, checked, onChange, disabled }) {
  return html`
    <label class="rf-ui-toggle" for=${id}>
      <input type="checkbox" class="rf-ui-switch" role="switch" id=${id} checked=${checked} disabled=${disabled}
        onChange=${(e) => onChange(e.currentTarget.checked)} />
      ${label}
    </label>`;
}

/** A checkbox for a value that an action saves later (a confirmation). */
export function Check({ id, label, checked, onChange }) {
  return html`
    <label class="rf-ui-toggle" for=${id}>
      <input type="checkbox" id=${id} checked=${checked} onChange=${(e) => onChange(e.currentTarget.checked)} />
      ${label}
    </label>`;
}
