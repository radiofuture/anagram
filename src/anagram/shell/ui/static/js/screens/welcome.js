// Welcome: the invite, your name (and email), the recovery kit, then
// institution and lab. No ORCID step in the main path: the
// invite is the proof. The join state comes from `join.state` events.
// A person with a recovery kit restores the keys instead (POST /api/recover).
// After the last step, Home shows what Anagram does now (store.arrived).
import { html, signal, useEffect, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';
import { invalidate, mutate, optional, useResource } from '../core/resource.js';
import { navigate } from '../core/router.js';
import {
  ActionButton,
  Button,
  Check,
  CopyField,
  Disclosure,
  DownloadLink,
  ErrorLine,
  Field,
  Screen,
  StatusLine,
  TaskPanel,
  TextArea,
  TextInput,
} from '../components/index.js';
import { IdentityForm } from '../parts/identity.js';

const STEPS = 3;
const BUSY = ['starting', 'signin', 'working', 'joined'];
const restoring = signal(false); // the person chose "I have a recovery kit"

// The state of the join or sign-in: the newest event, or what the server
// said when the screen opened.
function useJoin(info) {
  const live = store.live.join.value;
  const status = live || info?.status || { state: 'idle' };
  const { state } = status;
  useEffect(() => {
    // Only an invite to an ORCID iD, or a link of an ORCID iD, goes to ORCID.
    if (state === 'signin' && status.authorize_url) window.location.assign(status.authorize_url);
    // The keys exist: the overview has the next step.
    if (state === 'joined') invalidate(['/api/overview']);
  }, [state, status.authorize_url]);
  return status;
}

function start(path, body) {
  return async () => {
    store.live.join.value = await api('POST', path, body());
  };
}

function Working({ status }) {
  if (!BUSY.includes(status.state)) return null;
  const text = status.state === 'signin' ? t('welcome.opening') : t('welcome.working');
  return html`<${StatusLine} state="pending" text=${text} />`;
}

function PendingDevice({ status, again }) {
  const [error, setError] = useState('');
  return html`
    <${Screen} title=${t('welcome.pending_title')} lead=${t('welcome.pending_text')}>
      <${CopyField} id="device-request" label=${t('welcome.device_request')} value=${status.device_request || ''} rows=${4} />
      <p>${t('welcome.pending_then')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions ag-actions">
        <${ActionButton} label=${t('welcome.pending_action')} busyLabel=${t('welcome.signin_busy')}
          run=${start(again ? '/api/signin' : '/api/join', () => ({}))} errorTo=${setError} />
      </div>
    <//>`;
}

function InviteField({ value, onInput, help }) {
  return html`
    <${Field} id="invite" label=${t('welcome.invite_label')} help=${help}>
      <${TextArea} value=${value} onInput=${onInput} rows="3" spellcheck=${false} class="ag-invite"
        placeholder=${t('welcome.invite_placeholder')} />
    <//>`;
}

function SignInAgain({ status }) {
  const [error, setError] = useState('');
  const shown = error || (status.state === 'error' ? status.error : '');
  return html`
    <${Screen} title=${t('welcome.again_title')} lead=${t('welcome.again_lead')}>
      <${ErrorLine} text=${shown} />
      <${Working} status=${status} />
      <div class="rf-ui-actions ag-actions">
        <${ActionButton} label=${t('welcome.again_action')} busyLabel=${t('welcome.signin_busy')}
          run=${start('/api/signin', () => ({}))} errorTo=${setError} />
      </div>
    <//>`;
}

// The words of a pending invite: the community (or the lab) and the node,
// one time. With no invite: the person opens the link from the organizer.
function inviteWords(data) {
  if (!data) return { title: '', lead: '' };
  if (!data.invite || !data.community) return { title: t('welcome.invite_title'), lead: t('welcome.invite_open') };
  if (data.lab) {
    return {
      title: t('welcome.join_title', { name: data.lab }),
      lead: t('welcome.join_lab_lead', { community: data.community, host: data.host }),
    };
  }
  return {
    title: t('welcome.join_title', { name: data.community }),
    lead: t('welcome.join_lead', { host: data.host }),
  };
}

// A reader invite to an email address: the node sent a code there (R8-8).
function Code({ status }) {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  return html`
    <${Screen} title=${t('welcome.code_title')} lead=${t('welcome.code_lead', { email: status.email_hint || '' })}
      step=${{ n: 1, of: STEPS }}>
      <${Field} id="join-code" label=${t('welcome.code_label')}>
        <${TextInput} value=${code} onInput=${setCode} inputmode="numeric" autocomplete="one-time-code" maxlength="8" />
      <//>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions ag-actions">
        <${ActionButton} label=${t('welcome.code_action')} busyLabel=${t('welcome.working')}
          run=${start('/api/join/code', () => ({ code }))} errorTo=${setError} />
      </div>
    <//>`;
}

function Invite() {
  const ov = store.overview.value;
  const info = useResource('/api/join');
  const status = useJoin(info.data.value);
  const [typed, setTyped] = useState('');
  const [name, setName] = useState(null);
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const data = info.data.value;
  const pending = !!(data?.invite && data.community);
  if (status.state === 'pending_device')
    return html`<${PendingDevice} status=${status} again=${ov.can_sign_in_again} />`;
  if (status.state === 'code') return html`<${Code} status=${status} />`;
  if (ov.can_sign_in_again && !ov.joined) return html`<${SignInAgain} status=${status} />`;
  const shown = error || (status.state === 'error' ? status.error : '');
  const words = inviteWords(data);
  const busy = BUSY.includes(status.state);
  const shownName = name === null ? data?.name || '' : name;
  // An invite to a named person has the address (or the ORCID iD) already.
  const askEmail = !data?.contact;
  const body = (invite) => () => ({ invite, name: shownName, email: askEmail ? email : undefined });
  // The pending invite is the primary path: the name (and the email), then
  // one button. The paste field is a fallback for a computer where the link
  // did not open Anagram.
  return html`
    <${Screen} title=${words.title} lead=${words.lead} step=${{ n: 1, of: STEPS }} resources=${[info]}>
      ${() => html`
        <${ErrorLine} text=${shown} />
        <${Working} status=${status} />
        ${
          !busy &&
          html`
          <${Field} id="join-name" label=${t('welcome.name_label')}>
            <${TextInput} value=${shownName} onInput=${setName} autocomplete="name" />
          <//>
          ${
            askEmail &&
            html`
            <${Field} id="join-email" label=${t('welcome.email_label')} help=${t('welcome.email_help')}>
              <${TextInput} type="email" value=${email} onInput=${setEmail} autocomplete="email" />
            <//>`
          }
          ${
            pending &&
            html`
            <div class="rf-ui-actions ag-actions">
              <${ActionButton} label=${t('welcome.join_action')} busyLabel=${t('welcome.working')}
                run=${start('/api/join/start', body(undefined))} errorTo=${setError} />
            </div>`
          }
          <${Disclosure} summary=${t('welcome.use_invite')}>
            <${InviteField} value=${typed} onInput=${setTyped} help=${t('welcome.invite_help')} />
            <div class="rf-ui-actions">
              <${ActionButton} kind=${pending ? 'secondary' : 'primary'} label=${t('welcome.invite_action')}
                busyLabel=${t('welcome.working')} errorTo=${setError}
                run=${start('/api/join/start', body(typed))} />
            </div>
          <//>
          <p class="ag-welcome-other">
            <button type="button" class="ag-link" onClick=${() => {
              restoring.value = true;
            }}>${t('welcome.have_kit')}</button>
          </p>`
        }`}
    <//>`;
}

// The text of a kit file that the person chose. The file stays in the page.
function readFile(file) {
  return new Promise((done, fail) => {
    const reader = new FileReader();
    reader.onload = () => done(String(reader.result || ''));
    reader.onerror = () => fail(new Error(t('welcome.restore_unread')));
    reader.readAsText(file);
  });
}

// A person who used Anagram on another computer: the recovery kit opens the
// locked backup of the keys. The kit file or its pasted text; one action.
function Restore() {
  const [file, setFile] = useState(null); // { name, text }
  const [pasted, setPasted] = useState('');
  const [error, setError] = useState('');
  const choose = async (e) => {
    const f = e.currentTarget.files?.[0];
    e.currentTarget.value = '';
    if (!f) return;
    setError('');
    try {
      setFile({ name: f.name, text: await readFile(f) });
    } catch (err) {
      setError(err.message);
    }
  };
  const restore = async () => {
    const kit = pasted.trim() || file?.text || '';
    if (!kit) throw new Error(t('welcome.restore_need'));
    await mutate('POST', '/api/recover', { kit }, { invalidate: ['/api/overview'] });
    restoring.value = false;
    store.arrived.value = true;
  };
  return html`
    <${Screen} title=${t('welcome.restore_title')} lead=${t('welcome.restore_lead')}>
      <div class="ag-kit-file">
        <label class="rf-ui-button rf-ui-button--secondary ag-file-button">
          <input type="file" class="rf-ui-sr-only" accept=".md,.txt,text/markdown,text/plain" onChange=${choose} />
          ${t(file ? 'welcome.restore_other' : 'welcome.restore_choose')}
        </label>
        ${file && html`<p class="ag-kit-name">${file.name}</p>`}
      </div>
      <${Disclosure} summary=${t('welcome.restore_paste')}>
        <${Field} id="kit-text" label=${t('welcome.restore_text')} hideLabel=${true}>
          <${TextArea} value=${pasted} onInput=${setPasted} rows="6" spellcheck=${false} class="ag-invite" />
        <//>
      <//>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions ag-actions">
        <${ActionButton} label=${t('welcome.restore_action')} busyLabel=${t('welcome.restore_busy')}
          run=${restore} errorTo=${setError} />
        <${Button} kind="quiet" onClick=${() => {
          restoring.value = false;
        }}>${t('welcome.restore_back')}<//>
      </div>
    <//>`;
}

function Kit() {
  const kit = useResource('/api/recovery-kit');
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  const next = async () => {
    if (!saved) throw new Error(t('welcome.kit_need'));
    await mutate('POST', '/api/recovery-kit/saved', undefined, { invalidate: ['/api/overview'] });
  };
  return html`
    <${Screen} title=${t('welcome.kit_title')} lead=${t('welcome.kit_lead')} step=${{ n: 2, of: STEPS }} resources=${[kit]}>
      ${() => html`
        ${
          kit.data.value.available
            ? html`
            <${TaskPanel} label=${t('welcome.kit_code')}>
              <p class="ag-proof-label">${t('welcome.kit_code')}</p>
              <p class="ag-kit-code">${kit.data.value.code}</p>
              <div class="rf-ui-actions">
                <${DownloadLink} href="/api/recovery-kit/file" filename="anagram-recovery-kit.md"
                  label=${t('welcome.kit_download')} />
              </div>
            <//>`
            : html`<p class="rf-ui-help">${t('welcome.kit_gone')}</p>`
        }
        <${Check} id="kit-saved" label=${t('welcome.kit_check')} checked=${saved} onChange=${setSaved} />
        <p class="rf-ui-help">${t('welcome.kit_delete_note')}</p>
        <${ErrorLine} text=${error} />
        <div class="rf-ui-actions ag-actions">
          <${ActionButton} label=${t('welcome.kit_continue')} run=${next} errorTo=${setError} />
        </div>`}
    <//>`;
}

function Details() {
  // A person who came for a shared finding (a reader invite, R5 plan 6.5
  // rule 8) has no lab, and the setup ends on "Shared with me".
  const shared = useResource('/api/shared', { topics: ['shared'] });
  const reader = (optional(shared) || []).length > 0;
  return html`
    <${Screen} title=${t('details.setup_title')} lead=${t('details.lead')} step=${{ n: 3, of: STEPS }}>
      <${IdentityForm} saveLabel=${t('details.save_setup')} start=${reader ? 'later' : undefined} askName=${false}
        done=${() => {
          store.arrived.value = !reader;
          navigate(reader ? '#/sharing' : '#/home');
        }} />
    <//>`;
}

function View() {
  const ov = store.overview.value;
  // The sign-in makes the session before the join ends (device, lab, kit).
  // Stay on the first step until the join task is done, so that the kit
  // step reads the new kit. A join that failed after the sign-in (for
  // example a used lab link) shows its error on the first step.
  const task = store.live.join.value || ov.join || {};
  // ORCID sends the person back here after a link from Account.
  useEffect(() => {
    if (task.state === 'linked' && ov.joined) navigate('#/account');
  }, [task.state]);
  const joining = ['starting', 'signin', 'code', 'working'].includes(task.state);
  const failed = task.state === 'error' && !ov.kit_saved;
  if (!ov.joined && restoring.value) return html`<${Restore} key="restore" />`;
  if (!ov.joined || joining || failed) return html`<${Invite} key="invite" />`;
  if (!ov.kit_saved) return html`<${Kit} key="kit" />`;
  return html`<${Details} key="details" />`;
}

export const screen = { id: 'welcome', path: '/welcome', View };
