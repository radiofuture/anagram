// A hash that no screen has.
import { html } from '../core/html.js';
import { t } from '../core/copy.js';
import { Screen } from '../components/Screen.js';

function View() {
  return html`
    <${Screen} title=${t('notfound.title')}>
      <p><a href="#/">${t('notfound.home')}</a></p>
    <//>`;
}

export const screen = { id: 'notfound', path: null, View };
