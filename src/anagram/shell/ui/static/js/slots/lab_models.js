// Slot view `lab.models` of track R4 (step 11b): the model of a lab, in the
// lab settings. A PI or an admin sets the default model of the members and
// whether an outside model may read the text of the lab space (the settings
// sections `models` and `disclosure`). A member reads them. No key goes into
// the lab record: each member types a key for a cloud model.
// Routes: `GET /api/labs/{id}/settings`, `PUT /api/labs/{id}/models`.
// Words: `copy/models.json`.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { mutate, optional, useResource } from '../core/resource.js';
import { provide } from '../core/slots.js';
import { Facts, Section, StatusLine } from '../components/index.js';
import { ModelForm, whereOf } from '../parts/model_form.js';

const labIdOf = (lab) => (typeof lab === 'string' ? lab : lab && (lab.id || lab.lab_id));
const settingsPath = (id) => `/api/labs/${encodeURIComponent(id)}/settings`;

function modelText(p) {
  if (!p) return t('models.lab_each');
  const where = whereOf(p);
  if (where === 'university') return t('models.lab_at', { model: p.model, host: p.label });
  return t('models.lab_cloud', { model: p.model, name: t(`models.cloud_${p.provider}`) });
}

function LabModels({ lab }) {
  const id = labIdOf(lab);
  const path = settingsPath(id);
  const st = optional(useResource(path, { topics: ['lab'] }));
  const [saved, setSaved] = useState('');
  if (!st) return null;
  const p = (st.settings.models?.profiles || [])[0] || null;
  const labText = Boolean(p) && (st.settings.disclosure?.allow_external || []).length > 0;
  if (!st.can_edit) {
    return html`
      <${Section} id="lab-models-title" title=${t('models.lab_title')}>
        <${Facts} rows=${[
          [t('models.lab_model'), modelText(p)],
          [t('models.lab_space_text'), t(p && labText ? 'models.lab_text_out' : 'models.lab_text_home')],
        ]} />
        ${
          p &&
          p.provider !== 'ollama' &&
          p.provider !== 'openai_compatible' &&
          html`<p class="rf-ui-help">${t('models.lab_key_each')}</p>`
        }
      <//>`;
  }
  const save = async ({ profile, lab_text: text }) => {
    setSaved('');
    await mutate(
      'PUT',
      `/api/labs/${encodeURIComponent(id)}/models`,
      { profile, lab_text: text },
      { invalidate: [path] },
    );
    setSaved(t('models.lab_saved'));
    announce(t('models.lab_saved'));
  };
  const key = `${JSON.stringify(p)}-${labText}`;
  return html`
    <${Section} id="lab-models-title" title=${t('models.lab_title')}>
      <p class="rf-ui-help">${t('models.lab_help')}</p>
      <${ModelForm} key=${key} lab=${true} start=${p} labText=${labText} onSubmit=${save}
        submitLabel=${t('models.lab_save')} busyLabel=${t('models.saving')} />
      <${StatusLine} state="saved" text=${saved} />
    <//>`;
}

provide('lab.models', { order: 50, View: LabModels });
