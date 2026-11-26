// One per screen. It sets the title, the document title, and the state of
// the work area: main[data-screen][data-state=loading|ready|error].
//
//   <${Screen} title=${t('sources.title')} resources=${[sources]}>
//     ${() => html`… the content, made when the data is there …`}
//   <//>
import { html, useEffect, useLayoutEffect, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { route } from '../core/router.js';

function stateOf(resources) {
  if (resources.some((r) => r.data.value === null && r.error.value)) return 'error';
  if (resources.some((r) => r.data.value === null)) return 'loading';
  return 'ready';
}

// A first load shows words only if it is slow. No spinner.
function Loading({ text }) {
  const [show, setShow] = useState(false);
  useEffect(() => {
    const timer = setTimeout(() => setShow(true), 400);
    return () => clearTimeout(timer);
  }, []);
  return show ? html`<p class="ag-empty" role="status">${text}</p>` : null;
}

function LoadError({ resources }) {
  const failed = resources.find((r) => r.data.value === null && r.error.value);
  return html`
    <p class="rf-ui-error" role="alert">${failed.error.value.message}</p>
    <div class="rf-ui-actions">
      <button type="button" class="rf-ui-button rf-ui-button--secondary"
        onClick=${() => {
          for (const r of resources) r.reload();
        }}>${t('common.try_again')}</button>
    </div>`;
}

export function Screen({ id, title, back, lead, step, resources = [], loadingText, children }) {
  const screenId = id || (route.value ? route.value.id : '');
  const state = stateOf(resources);
  useLayoutEffect(() => {
    const main = document.getElementById('main');
    if (!main) return;
    main.dataset.screen = screenId;
    main.dataset.state = state;
  }, [screenId, state]);
  useEffect(() => {
    document.title = title ? t('common.doc_title', { title }) : t('common.product');
  }, [title]);
  let body = null;
  if (state === 'error') body = html`<${LoadError} resources=${resources} />`;
  else if (state === 'loading') body = html`<${Loading} text=${loadingText || t('common.loading')} />`;
  else body = typeof children === 'function' ? children() : children;
  return html`
    ${back && html`<p class="ag-back"><a href=${back.href}>${back.label}</a></p>`}
    ${step && html`<p class="ag-step">${t('common.step', step)}</p>`}
    <h1 class="ag-title" tabindex="-1">${title}</h1>
    ${lead && html`<p class="ag-lead">${lead}</p>`}
    ${body}`;
}
