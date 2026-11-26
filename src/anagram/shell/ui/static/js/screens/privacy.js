// What leaves this computer: each data flow, in one list (GET /api/flows).
import { html } from '../core/html.js';
import { t } from '../core/copy.js';
import { useResource } from '../core/resource.js';
import { Facts, Screen } from '../components/index.js';

function View() {
  const flows = useResource('/api/flows');
  return html`
    <${Screen} title=${t('privacy.title')} lead=${t('privacy.lead')} resources=${[flows]}>
      ${() => html`
        <ol class="ag-flows" aria-label=${t('privacy.list')}>
          ${flows.data.value.map(
            (f) => html`
            <li class="ag-flow" key=${f.id}>
              <h2 class="ag-subtitle">${f.to}</h2>
              <${Facts} rows=${[[t('privacy.what'), f.what], [t('privacy.when'), f.when], [t('privacy.can_see'), f.can_see]]} />
            </li>`,
          )}
        </ol>`}
    <//>`;
}

export const screen = { id: 'privacy', path: '/privacy', nav: { group: 'foot', order: 20 }, View };
