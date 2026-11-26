// Timestamp a finding from one draft: check the claim and the evidence, then
// confirm. Back returns to Findings with its scroll position.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { api } from '../core/api.js';
import { announce } from '../core/a11y.js';
import { cleanText, fmtDate } from '../core/format.js';
import { markSetDown } from '../core/motion.js';
import { mutate, useResource } from '../core/resource.js';
import { href, navigate } from '../core/router.js';
import {
  ActionButton,
  CheckList,
  Empty,
  ErrorLine,
  Field,
  Screen,
  StatusLine,
  TextInput,
} from '../components/index.js';
import { polarityWord } from './library.js';

function Form({ draft, settings }) {
  const selectable = draft.items.filter((i) => i.selectable).map((i) => i.key);
  const [claim, setClaim] = useState(cleanText(draft.claim_suggestion));
  const [keys, setKeys] = useState(selectable);
  const [error, setError] = useState('');
  const items = draft.items.map((i) => ({
    value: i.key,
    label: i.name,
    fixed: !i.selectable,
    help: i.selectable
      ? [i.kind, fmtDate(i.time), i.third_party ? t('draft.third_party') : null].filter(Boolean).join(', ')
      : t('draft.with_source', { kind: i.kind }),
  }));
  const provider = settings.model.enabled
    ? settings.providers.find((p) => p.id === settings.model.provider)?.label || t('draft.provider')
    : null;
  const redraft = async () => {
    const d = await api('POST', `/api/drafts/${encodeURIComponent(draft.id)}/model`);
    if (d.claim_suggestion) setClaim(cleanText(d.claim_suggestion));
  };
  const stamp = async () => {
    const f = await mutate(
      'POST',
      '/api/findings',
      { draft_id: draft.id, claim, keys },
      { invalidate: ['/api/findings', '/api/drafts', '/api/suggestions'] },
    );
    announce(t('draft.done'));
    markSetDown(f.root);
    navigate(href('finding', { root: f.root }), { replace: true });
  };
  // "Later" and "Not a finding" (R4 routes). Back to the library after each.
  const act = async (action) => {
    await mutate(
      'POST',
      `/api/suggestions/${encodeURIComponent(draft.id)}`,
      { action },
      { invalidate: ['/api/suggestions', '/api/drafts'] },
    );
    announce(t(action === 'later' ? 'draft.later_done' : 'draft.dismiss_done'));
    navigate(href('library'), { replace: true });
  };
  return html`
    ${polarityWord(draft) && html`<p class="rf-ui-help" data-testid="polarity">${polarityWord(draft)}</p>`}
    <${Field} id="claim" label=${t('draft.claim')} help=${t('draft.claim_help')}>
      <${TextInput} value=${claim} onInput=${setClaim} max=${500} />
    <//>
    ${
      provider &&
      html`
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('draft.model', { provider })} busyLabel=${t('draft.model_busy')}
          run=${redraft} errorTo=${setError} />
      </div>`
    }
    <${CheckList} legend=${t('draft.evidence')} name="evidence" items=${items} value=${keys} onChange=${setKeys} />
    <${StatusLine} state="pending" text=${t('draft.exact')} />
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions ag-actions">
      <${ActionButton} label=${t('draft.stamp')} busyLabel=${t('draft.stamp_busy')} run=${stamp} errorTo=${setError} />
      <${ActionButton} kind="quiet" label=${t('draft.later')} busyLabel=${t('draft.later_busy')} run=${() => act('later')} errorTo=${setError} />
      <${ActionButton} kind="quiet" label=${t('draft.dismiss')} busyLabel=${t('draft.dismiss_busy')} run=${() => act('dismiss')} errorTo=${setError} />
    </div>`;
}

function View({ params }) {
  const drafts = useResource('/api/suggestions', { topics: ['draft.changed', 'suggestion'] });
  const settings = useResource('/api/settings');
  const draft = drafts.data.value ? drafts.data.value.find((d) => d.id === params.id) : null;
  const back = { href: href('library'), label: t('draft.back') };
  return html`
    <${Screen} title=${t('draft.title')} back=${back} resources=${[drafts, settings]}
      lead=${draft ? cleanText(draft.reason) || t('draft.lead', { source: draft.title }) : null}>
      ${() =>
        draft
          ? html`<${Form} key=${draft.id} draft=${draft} settings=${settings.data.value} />`
          : html`<${Empty} text=${t('draft.gone')} action=${{ href: href('library'), label: t('draft.back') }} />`}
    <//>`;
}

export const screen = { id: 'draft', path: '/draft/:id', parent: 'library', View };
