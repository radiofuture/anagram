// A value to copy, and a file to download.
import { html, useEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';

/** A read-only value with a "Copy" action. The label says "Copied" only after the copy is done. */
export function CopyField({ id, label, value, rows = 3 }) {
  const [copied, setCopied] = useState(false);
  const field = useRef(null);
  useEffect(() => {
    setCopied(false);
  }, [value]);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      // No clipboard access: select the text, so that the person can copy it.
      field.current.focus();
      field.current.select();
    }
  };
  return html`
    <div class="rf-ui-field ag-copy">
      <label for=${id}>${label}</label>
      <textarea class="rf-ui-input ag-code-area" id=${id} rows=${rows} readonly spellcheck=${false} ref=${field}
        value=${value}></textarea>
      <div class="rf-ui-actions">
        <button type="button" class="rf-ui-button rf-ui-button--secondary" onClick=${copy}>
          ${copied ? t('common.copied') : t('common.copy')}
        </button>
      </div>
    </div>`;
}

/** A link that saves a file. */
export function DownloadLink({ href, label, filename = '', kind = 'secondary', name }) {
  const cls = kind === 'link' ? 'ag-small-link' : `rf-ui-button${kind === 'primary' ? '' : ` rf-ui-button--${kind}`}`;
  return html`<a class=${cls} href=${href} download=${filename} aria-label=${name}>${label}</a>`;
}
