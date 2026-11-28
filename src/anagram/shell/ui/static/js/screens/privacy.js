// What leaves this computer: each data flow, grouped by local, active, and
// optional (GET /api/flows).
import { html } from '../core/html.js';
import { t } from '../core/copy.js';
import { useResource } from '../core/resource.js';
import { Facts, Screen, Section } from '../components/index.js';

const GROUPS = ['local', 'active', 'optional'];

function FlowGroup({ group, items }) {
  if (!items.length) return null;
  return html`
    <${Section} id=${`flows-${group}`} title=${t(`privacy.group_${group}`)}>
      <ol class="ag-flows" aria-label=${t('privacy.list')}>
        ${items.map(
          (f) => html`
          <li class="ag-flow" key=${f.id}>
            <h3 class="ag-subtitle">${f.to}</h3>
            <${Facts} rows=${[[t('privacy.what'), f.what], [t('privacy.when'), f.when], [t('privacy.can_see'), f.can_see]]} />
          </li>`,
        )}
      </ol>
    <//>`;
}

function View() {
  const flows = useResource('/api/flows', {
    topics: [['models', 'state'].join('.'), ['assistant', 'changed'].join('.'), 'enclave.changed', 'source'],
  });
  return html`
    <${Screen} title=${t('privacy.title')} lead=${t('privacy.lead')} resources=${[flows]}>
      ${() => {
        const all = flows.data.value;
        return html`
          ${GROUPS.map((g) => html`<${FlowGroup} key=${g} group=${g} items=${all.filter((f) => (f.group || 'optional') === g)} />`)}`;
      }}
    <//>`;
}

export const screen = { id: 'privacy', path: '/privacy', nav: { group: 'foot', order: 20 }, View };
