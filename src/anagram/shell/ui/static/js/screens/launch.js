// Shown when the server refuses the cookie (401). It has no route. The one
// next step opens the app (URL scheme of track R1), which opens a new window.
import { html, useEffect } from '../core/html.js';
import { t } from '../core/copy.js';

function View() {
  useEffect(() => {
    document.title = t('common.doc_title', { title: t('launch.title') });
  }, []);
  return html`
    <h1 class="ag-title">${t('launch.title')}</h1>
    <p class="ag-lead">${t('launch.text')}</p>
    <div class="rf-ui-actions">
      <a class="rf-ui-button" href="anagram://open">${t('launch.open')}</a>
    </div>`;
}

export const screen = { id: 'launch', View };
