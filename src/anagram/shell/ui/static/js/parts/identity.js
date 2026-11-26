// The form for name, institution, and lab. The welcome screen (step 3) and
// the details screen use it. js/parts/ holds views that more than one screen uses.
import { html, useLayoutEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { search } from '../core/api.js';
import { store } from '../core/store.js';
import { mutate, useDraft, useResource } from '../core/resource.js';
import { openHeight } from '../core/motion.js';
import { ActionButton, ChoiceGroup, ErrorLine, Field, SearchSelect, TextInput } from '../components/index.js';

// A field that a choice reveals opens from height 0 (motion recipe D1).
function Reveal({ show, children }) {
  const ref = useRef(null);
  const first = useRef(true);
  useLayoutEffect(() => {
    if (!first.current && show && ref.current) openHeight(ref.current);
    first.current = false;
  }, [show]);
  return show ? html`<div ref=${ref}>${children}</div>` : null;
}

/**
 * `done()` runs after the save. `saveLabel` names the action. `start`: the lab
 * choice for a person with no lab. `askName` false: the join step had the
 * name field, so the setup does not ask again.
 */
export function IdentityForm({ saveLabel, done, start, askName = true }) {
  const ov = store.overview.value;
  const labs = useResource('/api/labs/mine');
  // The name can come after the form opens: a join writes it to the
  // community server at its end. The field takes it if the person did not type.
  const nameDraft = useDraft(ov.name || '');
  const name = nameDraft.value;
  const setName = nameDraft.set;
  const [institution, setInstitution] = useState(
    ov.institution ? { id: ov.institution.id, label: ov.institution.name } : null,
  );
  const [picked, setPicked] = useState(false);
  const [lab, setLab] = useState(null);
  const [newLab, setNewLab] = useState('');
  const [error, setError] = useState('');
  const mine = labs.data.value;
  if (mine === null) return html`<${ErrorLine} text=${labs.error.value?.message} />`;

  const options = [
    ...mine.map((l) => ({ value: l.id, label: l.name, help: t(l.i_lead ? 'details.lab_lead' : 'details.lab_member') })),
    { value: 'new', label: t('details.lab_new'), help: t('details.lab_new_help') },
    { value: 'later', label: t('details.lab_later'), help: t('details.lab_later_help') },
  ];
  const choice = lab || (ov.lab ? ov.lab.id : mine.length ? mine[0].id : start || 'new');

  const save = async () => {
    if (!institution) throw new Error(t('details.need_institution'));
    const body = { name, ror: institution.id, institution_name: institution.label };
    if (choice === 'new') {
      if (!newLab.trim()) throw new Error(t('details.need_lab'));
      body.new_lab = newLab;
    } else if (choice !== 'later') {
      body.lab_id = choice;
    }
    await mutate('PUT', '/api/identity', body, { invalidate: ['/api/overview', '/api/labs/mine'] });
    done();
  };

  return html`
    ${
      (askName || !name) &&
      html`
      <${Field} id="name" label=${t('details.name')}>
        <${TextInput} value=${name} onInput=${setName} autocomplete="name" />
      <//>`
    }
    <div class="ag-group">
      <${SearchSelect} id="institution" label=${t('details.institution')}
        placeholder=${t('details.institution_placeholder')}
        search=${(q, signal) => search(`/api/institutions?q=${encodeURIComponent(q)}`, signal)}
        onChange=${(s) => {
          if (s.selected) {
            setInstitution(s.selected);
            setPicked(true);
          }
        }} />
      ${institution && !picked && html`<p class="rf-ui-help">${t('details.institution_now', { name: institution.label })}</p>`}
    </div>
    <${ChoiceGroup} legend=${t('details.lab_legend')} name="lab" value=${choice} options=${options} onChange=${setLab} />
    <${Reveal} show=${choice === 'new'}>
      <${Field} id="new-lab" label=${t('details.new_lab')}>
        <${TextInput} value=${newLab} onInput=${setNewLab} placeholder=${t('details.new_lab_placeholder')} />
      <//>
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions ag-actions">
      <${ActionButton} label=${saveLabel} busyLabel=${t('details.save_busy')} run=${save} errorTo=${setError} />
    </div>`;
}
