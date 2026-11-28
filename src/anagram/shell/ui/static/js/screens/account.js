// Account: details, devices, recovery, guardians, sign out. Other
// tracks add sections through the slot `account.sections` (this computer, the model).
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { api, search } from '../core/api.js';
import { store } from '../core/store.js';
import { invalidate, mutate, useResource } from '../core/resource.js';
import { href, navigate } from '../core/router.js';
import {
  ActionButton,
  Button,
  ChipList,
  Disclosure,
  DownloadLink,
  KitCode,
  ErrorLine,
  Facts,
  Field,
  Row,
  RowList,
  Screen,
  SearchSelect,
  Section,
  Slot,
  TextArea,
} from '../components/index.js';

function Alerts({ alerts }) {
  if (!alerts.length) return null;
  return html`
    <section class="ag-alert" role="alert" aria-labelledby="alert-title">
      <h2 class="ag-section" id="alert-title">${t('account.alert_title')}</h2>
      <p>${t('account.alert_text')}</p>
      <${Disclosure} kind="details" summary=${t('account.alert_log')}>
        <${Facts} rows=${alerts.map((a, i) => [t('account.alert_n', { n: i + 1 }), a])} />
      <//>
    </section>`;
}

function Me({ ov }) {
  return html`
    <${Section} id="me-title" title=${t('account.me_title')}>
      <${Facts} rows=${[
        [t('account.name'), ov.name || t('common.not_given')],
        ...(ov.email ? [[t('account.email'), ov.email]] : []),
        ...(ov.orcid ? [[t('account.orcid'), ov.orcid]] : []),
        [t('account.institution'), ov.institution ? ov.institution.name : t('common.not_given')],
        [t('account.lab'), ov.lab ? ov.lab.name : t('common.not_given')],
        [t('account.community'), ov.community],
      ]} />
      <p><a href=${href('details')}>${t('account.change')}</a></p>
      ${!ov.orcid && html`<${LinkOrcid} />`}
      ${ov.organizer && html`<${OrganizerPage} />`}
      <${Disclosure} kind="details" summary=${t('common.details')}>
        <${Facts} rows=${[[t('account.server'), ov.details.node], [t('account.subject'), ov.details.subject]]} />
      <//>
    <//>`;
}

// Optional: ORCID confirms the iD on its own page, then
// Anagram opens again on Account.
function LinkOrcid() {
  const [error, setError] = useState('');
  const run = async () => {
    const view = await api('POST', '/api/orcid/link');
    store.live.join.value = view;
    if (view.state === 'error') throw new Error(view.error);
    if (view.authorize_url) window.location.assign(view.authorize_url);
  };
  return html`
    <p class="rf-ui-help">${t('account.orcid_link_help')}</p>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${t('account.orcid_link')} busyLabel=${t('account.orcid_link_busy')}
        run=${run} errorTo=${setError} />
    </div>`;
}

// R8: an organizer opens the organizer page with a one-time link, with no
// ORCID sign-in. The tab opens first, so the browser does not block it.
function OrganizerPage() {
  const [error, setError] = useState('');
  const run = async () => {
    const tab = window.open('', '_blank');
    try {
      const { url } = await api('POST', '/api/organizer/open');
      if (tab) {
        tab.opener = null;
        tab.location = url;
      } else window.location.assign(url);
    } catch (e) {
      if (tab) tab.close();
      throw e;
    }
  };
  return html`
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${t('account.organizer')} busyLabel=${t('account.organizer_busy')}
        run=${run} errorTo=${setError} />
    </div>`;
}

function Devices({ acc }) {
  const [request, setRequest] = useState('');
  const [error, setError] = useState('');
  const add = async () => {
    await mutate('POST', '/api/devices', { request }, { invalidate: ['/api/account'] });
    setRequest('');
  };
  return html`
    <${Section} id="devices-title" title=${t('account.devices_title')}>
      <${RowList} items=${acc.devices} keyOf=${(d) => d.id} label=${t('account.devices_title')}
        render=${(d) => html`
          <${Row} title=${d.this ? t('account.this_device') : t('account.other_device')}>
            <${Disclosure} kind="details" summary=${t('account.device_key')}>
              <${Facts} rows=${[[t('account.device_key'), d.id]]} />
            <//>
          <//>`} />
      <${Disclosure} summary=${t('account.add_device')}>
        <p class="rf-ui-help">${t('account.add_device_help')}</p>
        <${Field} id="device-request" label=${t('account.device_request')}>
          <${TextArea} value=${request} onInput=${setRequest} rows="3" spellcheck=${false} class="ag-code-area" />
        <//>
        <${ErrorLine} text=${error} />
        <div class="rf-ui-actions">
          <${ActionButton} kind="secondary" label=${t('account.add_device_action')} busyLabel=${t('account.add_device_busy')}
            run=${add} errorTo=${setError} />
        </div>
      <//>
    <//>`;
}

function NewKit() {
  const [code, setCode] = useState(null);
  const [error, setError] = useState('');
  return html`
    <div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${t('account.kit_new')} busyLabel=${t('account.kit_new_busy')}
        run=${async () => setCode((await api('POST', '/api/recovery-kit/new')).code)} errorTo=${setError} />
    </div>
    <${ErrorLine} text=${error} />
    ${
      code &&
      html`
      <div class="ag-kit">
        <p class="rf-ui-help">${t('account.kit_new_text')}</p>
        <${KitCode} code=${code} />
        <div class="rf-ui-actions">
          <${DownloadLink} href="/api/recovery-kit/file" filename="anagram-recovery-kit.md" label=${t('account.kit_download')} />
          <${ActionButton} kind="secondary" label=${t('account.kit_saved_action')} busyLabel=${t('account.kit_saved_busy')}
            run=${async () => {
              await mutate('POST', '/api/recovery-kit/saved', undefined, {
                invalidate: ['/api/account', '/api/overview'],
              });
              setCode(null);
            }} errorTo=${setError} />
        </div>
      </div>`
    }`;
}

function Guardians({ acc }) {
  const [current, setCurrent] = useState(null);
  const [chosen, setChosen] = useState([]);
  const [error, setError] = useState('');
  const add = () => {
    if (current && !chosen.some((p) => p.id === current.id)) setChosen([...chosen, current]);
  };
  const save = async () => {
    if (chosen.length < 2) throw new Error(t('account.guardians_need'));
    await mutate(
      'POST',
      '/api/guardians',
      { people: chosen.map((p) => p.id), threshold: 2 },
      { invalidate: ['/api/account'] },
    );
    setChosen([]);
  };
  return html`
    <h3 class="ag-subtitle">${t('account.guardians_title')}</h3>
    ${
      acc.guardians
        ? html`<p>${t('account.guardians_now', { n: acc.guardians.threshold, people: acc.guardians.people.join(', ') })}</p>`
        : html`<p class="rf-ui-help">${t('account.guardians_help')}</p>`
    }
    <${Disclosure} summary=${t(acc.guardians ? 'account.guardians_new' : 'account.guardians_choose')}>
      <${SearchSelect} id="guardian" label=${t('account.guardians_search')} placeholder=${t('account.person_placeholder')}
        search=${(q, signal) => search(`/api/people?q=${encodeURIComponent(q)}`, signal)} onChange=${(s) => setCurrent(s.selected)} />
      <div class="rf-ui-actions">
        <${Button} kind="secondary" onClick=${add}>${t('account.guardians_add')}<//>
      </div>
      <${ChipList} items=${chosen} label=${t('account.guardians_chosen')}
        removeLabel=${(p) => t('account.guardians_remove', { name: p.label })}
        onRemove=${(p) => setChosen(chosen.filter((x) => x.id !== p.id))} />
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('account.guardians_save')} busyLabel=${t('account.guardians_save_busy')}
          run=${save} errorTo=${setError} />
      </div>
    <//>`;
}

function Requests({ acc }) {
  const [error, setError] = useState('');
  if (!acc.requests.length) return null;
  return html`
    <h3 class="ag-subtitle">${t('account.requests_title')}</h3>
    <p class="rf-ui-help">${t('account.requests_help')}</p>
    <${RowList} items=${acc.requests} keyOf=${(r) => r.id} label=${t('account.requests_title')}
      render=${(r) => html`
        <${Row} title=${t('account.request', { person: r.person })}
          action=${
            r.check_ok
              ? html`<${ActionButton} kind="secondary" label=${t('account.approve_for', { person: r.person })}
                busyLabel=${t('account.approve_busy')} errorTo=${setError}
                run=${() => mutate('POST', '/api/guardians/approve', { request_id: r.id }, { invalidate: ['/api/account'] })} />`
              : html`<span class="rf-ui-error ag-row-fact">${t('account.request_bad')}</span>`
          } />`} />
    <${ErrorLine} text=${error} />`;
}

function Recovery({ acc }) {
  return html`
    <${Section} id="recovery-title" title=${t('account.recovery_title')}>
      <p>${t(acc.kit_saved ? 'account.kit_saved' : 'account.kit_unsaved')}</p>
      <${NewKit} />
      <${Guardians} acc=${acc} />
      <${Requests} acc=${acc} />
    <//>`;
}

// Only a person with an email address or an ORCID iD can be found by one.
function Findable({ ov }) {
  const on = Boolean(ov.findable || ov.findable_by_orcid);
  const [error, setError] = useState('');
  if (!ov.email && !ov.orcid) return null;
  return html`
    <${Section} id="findable-title" title=${t('account.findable_title')}>
      <p>${t(on ? 'account.findable_on' : 'account.findable_off')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t(on ? 'account.turn_off' : 'account.turn_on')} busyLabel=${t('account.saving')}
          run=${() => mutate('PUT', '/api/settings/findable', { on: !on }, { invalidate: ['/api/overview'] })} errorTo=${setError} />
      </div>
    <//>`;
}

function SignOut() {
  const [error, setError] = useState('');
  const out = async () => {
    await api('POST', '/api/logout');
    await invalidate(['/api/overview']);
    navigate('#/welcome');
  };
  return html`
    <${Section} id="signout-title" title=${t('account.signout_title')}>
      <p class="rf-ui-help">${t('account.signout_help')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('account.signout')} busyLabel=${t('account.signout_busy')} run=${out} errorTo=${setError} />
      </div>
    <//>`;
}

function View() {
  const ov = store.overview.value;
  const acc = useResource('/api/account', { topics: ['overview.changed'] });
  return html`
    <${Screen} title=${t('account.title')} resources=${[acc]}>
      ${() => html`
        <${Alerts} alerts=${acc.data.value.alerts} />
        <${Me} ov=${ov} />
        <${Devices} acc=${acc.data.value} />
        <${Recovery} acc=${acc.data.value} />
        <${Findable} ov=${ov} />
        <${Slot} name="account.sections" />
        <${SignOut} />`}
    <//>`;
}

export const screen = { id: 'account', path: '/account', nav: { group: 'foot', order: 10 }, View };
