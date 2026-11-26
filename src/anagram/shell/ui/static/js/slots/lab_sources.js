// Slot view `lab.settings` of track R3 (step S15): the sections
// `oauth_clients` and `sources` of the lab settings. The lab screen
// renders `<Slot name="lab.settings" props=${{ lab }} />`; `lab` is the lab
// ID or an object with `id` (or `lab_id`). A PI or admin changes the values;
// a member reads them. Routes: `GET /api/source-settings`,
// `PUT|DELETE /api/source-settings/{lab}/clients/{provider}`,
// `PUT /api/source-settings/{lab}/sources`. Words: `copy/labsources.json`.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { provide } from '../core/slots.js';
import { mutate, optional, useResource } from '../core/resource.js';
import { ActionButton, CheckList, ChoiceGroup, ErrorLine, Facts, Section, StatusLine } from '../components/index.js';
import { ClientForm, PROVIDERS, named } from '../parts/sources_connect.js';

const labIdOf = (lab) => (typeof lab === 'string' ? lab : lab && (lab.id || lab.lab_id));

function Client({ lab, provider }) {
  const name = PROVIDERS[provider];
  const id = `lab-client-${provider}`;
  return html`
    <${Section} id=${id} title=${t('labsources.client_title', { provider: name })}>
      ${
        lab.can_edit
          ? html`<${ClientForm} lab=${lab} provider=${provider} />`
          : html`
          <${Facts} rows=${[
            [
              t('labsources.client_state'),
              lab.clients[provider] ? t('labsources.client_set') : t('labsources.client_not_set'),
            ],
          ]} />
          <p class="rf-ui-help">${t('labsources.admin_only')}</p>`
      }
    <//>`;
}

function Rules({ lab, kinds }) {
  const all = kinds.map((k) => k.kind);
  const start = lab.sources.allowed_kinds === null ? all : lab.sources.allowed_kinds;
  const [allowed, setAllowed] = useState(start);
  const [def, setDef] = useState(lab.sources.lab_default);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const label = (kind) => kinds.find((k) => k.kind === kind)?.label || kind;
  if (!lab.can_edit) {
    return html`
      <${Section} id="lab-rules-title" title=${t('labsources.rules_title')}>
        <${Facts} rows=${[
          [t('labsources.allowed'), start.map(label).join(', ') || t('labsources.allowed_none')],
          [t('labsources.default'), t(`labsources.default_${def}`)],
        ]} />
        <p class="rf-ui-help">${t('labsources.admin_only')}</p>
      <//>`;
  }
  const save = async () => {
    setSaved('');
    const body = { allowed_kinds: allowed.length === all.length ? null : allowed, lab_default: def };
    await mutate('PUT', `/api/source-settings/${encodeURIComponent(lab.id)}/sources`, body, {
      invalidate: ['/api/source-settings', '/api/source-kinds'],
    });
    setSaved(t('labsources.saved'));
  };
  return html`
    <${Section} id="lab-rules-title" title=${t('labsources.rules_title')}>
      <${CheckList} legend=${t('labsources.allowed')} name="lab-kinds" value=${allowed} onChange=${setAllowed}
        items=${kinds.map((k) => ({ value: k.kind, label: k.label }))} />
      <${ChoiceGroup} legend=${t('labsources.default')} name="lab-default" value=${def} onChange=${setDef}
        options=${['private', 'lab'].map((v) => ({ value: v, label: t(`labsources.default_${v}`), help: t(`labsources.default_${v}_help`) }))} />
      <${ErrorLine} text=${error} />
      <${StatusLine} state="saved" text=${saved} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('labsources.save')} busyLabel=${t('labsources.saving')} run=${save} errorTo=${setError} />
      </div>
    <//>`;
}

function LabSources({ lab }) {
  const settings = useResource('/api/source-settings', { topics: ['lab'] });
  const data = optional(settings);
  const row = data?.labs.find((l) => l.id === labIdOf(lab));
  if (!row) return null;
  return html`
    <div class="ag-lab-sources">
      <${Client} key=${`google-${row.id}`} lab=${row} provider="google" />
      <${Client} key=${`notion-${row.id}`} lab=${row} provider="notion" />
      <${Rules} key=${`rules-${row.id}`} lab=${row} kinds=${named(data.kinds)} />
    </div>`;
}

provide('lab.settings', { order: 30, View: LabSources });
