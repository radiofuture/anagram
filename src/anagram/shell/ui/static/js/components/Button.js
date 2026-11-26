// Buttons. `kind`: 'primary' (blue), 'secondary' (outline), 'quiet'
// (underlined), 'danger'. One primary action for each task.
//
// ActionButton runs an action. While the action runs, the label changes in
// place to the name of the real work, and the button has aria-disabled. The
// width does not jump: the button keeps room for the longer label.
import { html, useEffect, useRef, useState } from '../core/html.js';
import { announce } from '../core/a11y.js';

function cls(kind, extra) {
  return `rf-ui-button${kind && kind !== 'primary' ? ` rf-ui-button--${kind}` : ''}${extra ? ` ${extra}` : ''}`;
}

export function Button({ kind = 'primary', href, children, class: extra, ...rest }) {
  if (href) return html`<a class=${cls(kind, extra)} href=${href} ...${rest}>${children}</a>`;
  return html`<button type="button" class=${cls(kind, extra)} ...${rest}>${children}</button>`;
}

/**
 * @param {{label: string, busyLabel?: string, run: () => Promise<void>, kind?: string,
 *   errorTo?: (message: string) => void, disabled?: boolean}} props
 *   An error of `run` goes to `errorTo` (an error line near the button). With
 *   no `errorTo`, the status region says it.
 */
export function ActionButton({ label, busyLabel, run, kind = 'primary', errorTo, disabled, ...rest }) {
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  useEffect(
    () => () => {
      alive.current = false;
    },
    [],
  );
  const click = async () => {
    if (busy || disabled) return;
    setBusy(true);
    if (errorTo) errorTo('');
    try {
      await run();
    } catch (err) {
      if (errorTo) errorTo(err.message);
      else announce(err.message);
    } finally {
      if (alive.current) setBusy(false);
    }
  };
  const working = busy && Boolean(busyLabel);
  return html`
    <button type="button" class=${cls(kind, 'ag-action')} aria-disabled=${busy || disabled ? 'true' : undefined}
      onClick=${click} ...${rest}>
      <span class="ag-action-label" data-on=${String(!working)} aria-hidden=${working ? 'true' : undefined}>${label}</span>
      ${
        busyLabel &&
        html`
        <span class="ag-action-label" data-on=${String(working)} aria-hidden=${working ? undefined : 'true'}>${busyLabel}</span>`
      }
    </button>`;
}
