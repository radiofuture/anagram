// Choose a folder of this computer (GET /api/browse). The place shows as a
// name relative to the home folder, not as an absolute path.
import { html, useEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { api } from '../core/api.js';
import { baseName, homePath } from '../core/format.js';
import { ActionButton, Button } from './Button.js';
import { ErrorLine } from './Status.js';

/**
 * @param {{onPick: (path: string) => Promise<void>, onCancel: () => void,
 *   pickLabel?: string, pickBusyLabel?: string}} props
 */
export function FolderPicker({ onPick, onCancel, pickLabel, pickBusyLabel }) {
  const [here, setHere] = useState(null);
  const [error, setError] = useState('');
  const title = useRef(null);
  const open = async (path) => {
    try {
      setHere(await api('GET', `/api/browse${path ? `?path=${encodeURIComponent(path)}` : ''}`));
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };
  useEffect(() => {
    open(null);
  }, []);
  useEffect(() => {
    if (here && title.current) title.current.focus();
  }, [here?.path]);
  if (!here) return html`<div class="ag-picker"><${ErrorLine} text=${error} /></div>`;
  return html`
    <div class="ag-picker">
      <h2 class="ag-subtitle" tabindex="-1" ref=${title}>${t('common.picker.title')}</h2>
      <p class="ag-picker-place">${baseName(here.path) || homePath(here.path)}
        <small class="rf-ui-help">${homePath(here.path)}</small></p>
      <div class="rf-ui-actions">
        <${ActionButton} label=${pickLabel || t('common.picker.pick')} busyLabel=${pickBusyLabel || t('common.picker.pick_busy')}
          run=${() => onPick(here.path)} errorTo=${setError} />
        ${here.parent && html`<${Button} kind="secondary" onClick=${() => open(here.parent)}>${t('common.picker.up')}<//>`}
        <${Button} kind="quiet" onClick=${onCancel}>${t('common.cancel')}<//>
      </div>
      <${ErrorLine} text=${error} />
      ${
        here.dirs.length
          ? html`
          <ul class="ag-folders" aria-label=${t('common.picker.inside')}>
            ${here.dirs.map(
              (d) => html`
              <li key=${d.path}><button type="button" class="ag-folder" onClick=${() => open(d.path)}>${d.name}</button></li>`,
            )}
          </ul>`
          : html`<p class="rf-ui-help">${t('common.picker.none')}</p>`
      }
    </div>`;
}
