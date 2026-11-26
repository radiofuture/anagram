// "Add to the lab space" on an item (track R2 step S12). Slot `item.actions`.
// The action shows only for a person in a lab, and not for an item that is
// already in a lab space. A finding goes to the lab through the share sheet
// ("My lab"), so the finding screen has one path to the lab.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { mutate, optional, useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { provide } from '../core/slots.js';
import { ActionButton, Button, Check, ChoiceGroup, ErrorLine, Sheet, openSheet } from '../components/index.js';

function AddSheet({ labs, body, title, files, close }) {
  const [lab, setLab] = useState(labs[0].id);
  const [attach, setAttach] = useState(false);
  const [error, setError] = useState('');
  const add = async () => {
    await mutate(
      'POST',
      `/api/labs/${encodeURIComponent(lab)}/space`,
      { ...body, attach },
      { invalidate: [`/api/labs/${encodeURIComponent(lab)}/space`] },
    );
    const name = labs.find((l) => l.id === lab).name;
    announce(t('lab.publish_done', { lab: name }));
    close({ lab, name });
  };
  return html`
    <${Sheet} title=${title}>
      ${
        labs.length > 1
          ? html`<${ChoiceGroup} legend=${t('lab.publish_which')} name="publish-lab" value=${lab}
            options=${labs.map((l) => ({ value: l.id, label: l.name }))} onChange=${setLab} />`
          : html`<p>${t('lab.publish_text', { lab: labs[0].name })}</p>`
      }
      ${files && html`<${Check} id="publish-file" label=${t('lab.publish_file')} checked=${attach} onChange=${setAttach} />`}
      <p class="rf-ui-help">${t('lab.publish_help')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('lab.publish_action')} busyLabel=${t('lab.publish_busy')} run=${add} errorTo=${setError} />
        <${Button} kind="quiet" onClick=${() => close(null)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

function AddButton({ body, title, files, inLab }) {
  const labs = optional(useResource('/api/labs/mine', { topics: ['lab'] }));
  const [done, setDone] = useState(null);
  if (!labs?.length || inLab) return null;
  if (done) {
    return html`<a class="ag-small-link" href=${href('lab', { id: done.lab, tab: 'space' })}>${t('lab.publish_open', { lab: done.name })}</a>`;
  }
  const open = async () => {
    const out = await openSheet(AddSheet, { labs, body, title, files });
    if (out) setDone(out);
  };
  return html`<${Button} kind="secondary" onClick=${open}>${t('lab.publish')}<//>`;
}

function ItemAction({ item }) {
  const inLab = String(item.space || '').startsWith('lab');
  return html`<${AddButton} body=${{ item: item.ref }} title=${t('lab.publish_title')} files=${true} inLab=${inLab} />`;
}

provide(['item', 'actions'].join('.'), { order: 50, View: ItemAction });
