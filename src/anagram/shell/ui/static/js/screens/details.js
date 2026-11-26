// Change your details: name, institution, and lab.
import { html } from '../core/html.js';
import { t } from '../core/copy.js';
import { href, navigate } from '../core/router.js';
import { Screen } from '../components/index.js';
import { IdentityForm } from '../parts/identity.js';

function View() {
  return html`
    <${Screen} title=${t('details.title')} lead=${t('details.lead')} back=${{ href: href('account'), label: t('details.back') }}>
      <${IdentityForm} saveLabel=${t('details.save')} done=${() => navigate(href('account'))} />
    <//>`;
}

export const screen = { id: 'details', path: '/account/details', parent: 'account', View };
