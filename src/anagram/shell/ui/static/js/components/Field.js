// A labelled input. `Field` gives the label, the help, and the error, and
// wires them to the input with aria-describedby. `TextInput` and `TextArea`
// inside a Field read its id. With `max` they show a character count, only
// when the text is near the limit (more than 80 % of it).
import { createContext, html, useContext } from '../core/html.js';
import { t } from '../core/copy.js';

const FieldContext = createContext(null);

export function Field({ id, label, help, error, hideLabel, children }) {
  const about = [help ? `${id}-help` : null, error ? `${id}-error` : null].filter(Boolean).join(' ');
  return html`
    <div class="rf-ui-field">
      <label for=${id} class=${hideLabel ? 'rf-ui-sr-only' : undefined}>${label}</label>
      ${help && html`<p class="rf-ui-help" id=${`${id}-help`}>${help}</p>`}
      <${FieldContext.Provider} value=${{ id, about, invalid: Boolean(error) }}>${children}<//>
      ${error && html`<p class="rf-ui-error" id=${`${id}-error`} role="alert">${error}</p>`}
    </div>`;
}

function Counter({ id, n, max }) {
  return html`
    <p class=${`ag-counter rf-ui-help${n >= max ? ' ag-counter--full' : ''}`} id=${id}>
      ${t('common.characters', { n, max })}
    </p>`;
}

const near = (value, max) => Boolean(max) && (value || '').length > max * 0.8;

function inputProps(props, field) {
  const { id, value, onInput, onCommit, max, label, describedBy, ...rest } = props;
  const useId = id || field?.id;
  const about = [describedBy, field && !id ? field.about : null, near(value, max) ? `${useId}-count` : null]
    .filter(Boolean)
    .join(' ');
  return {
    useId,
    attrs: {
      ...rest,
      id: useId,
      value: value || '',
      maxlength: max || undefined,
      'aria-label': label || undefined,
      'aria-describedby': about || undefined,
      'aria-invalid': field && !id && field.invalid ? 'true' : undefined,
      onInput: (e) => {
        if (onInput) onInput(e.currentTarget.value);
      },
      onChange: (e) => {
        if (onCommit) onCommit(e.currentTarget.value);
      },
    },
  };
}

/** `onInput(value)` on each change, `onCommit(value)` when the person leaves the field. */
export function TextInput(props) {
  const { useId, attrs } = inputProps(props, useContext(FieldContext));
  const cls = `rf-ui-input${props.class ? ` ${props.class}` : ''}`;
  return html`
    <input type="text" ...${attrs} class=${cls} />
    ${near(props.value, props.max) && html`<${Counter} id=${`${useId}-count`} n=${(props.value || '').length} max=${props.max} />`}`;
}

export function TextArea(props) {
  const { useId, attrs } = inputProps(props, useContext(FieldContext));
  const cls = `rf-ui-input ag-textarea${props.class ? ` ${props.class}` : ''}`;
  return html`
    <textarea rows="4" ...${attrs} class=${cls}></textarea>
    ${near(props.value, props.max) && html`<${Counter} id=${`${useId}-count`} n=${(props.value || '').length} max=${props.max} />`}`;
}
