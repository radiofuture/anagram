// The kinds that a member can connect, the setup of each, and the parts that
// the source detail uses again (sign in, what to include, who can read it).
// The kinds come from `GET /api/source-kinds`, so new source kinds show
// here automatically.
//
//   folder, Obsidian, Git          the folder picker
//   Zotero export                  the path of the file
//   ORCID works                    one action
//   Google Drive, Gmail, Notion    sign in at the provider (a one-use listener
//                                  on this computer), then choose what to read
//   Zotero web                     a pasted key
//
// A Google or Notion kind with no client for the lab says "Not set up for
// this lab" one time, on its tile. On select, the setup gives the one next
// step: a lab admin adds the client here (ClientForm, also the slot view of
// Lab settings); a member asks the lab admin.
import { createContext, html, useContext, useEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { api } from '../core/api.js';
import { mutate, optional, useResource } from '../core/resource.js';
import {
  ActionButton,
  Button,
  CheckList,
  ChoiceGroup,
  Disclosure,
  ErrorLine,
  Field,
  FolderPicker,
  StatusLine,
  TextInput,
} from '../components/index.js';

const CHANGED = ['/api/sources', '/api/drafts', '/api/suggestions'];
const PICK = new Set(['folder', 'obsidian', 'git']);
export const PROVIDERS = { google: 'Google', notion: 'Notion', zotero: 'Zotero' };
export const providerName = (k) => PROVIDERS[k.provider] || k.label;

/** Add one source. A lab space that is not ready is a calm sentence, not a fault. */
export async function addSource(body) {
  try {
    return await mutate('POST', '/api/sources', body, { invalidate: CHANGED });
  } catch (err) {
    if (err.data && err.data.code === 'space_unavailable') throw new Error(t('sources.space_unavailable'));
    throw err;
  }
}

/** Change one source (`PATCH`). Gives the new row. */
export function patchSource(id, body) {
  return mutate('PATCH', `/api/sources/${encodeURIComponent(id)}`, body, {
    invalidate: [...CHANGED, `/api/sources/${encodeURIComponent(id)}`],
  });
}

// The space of the source in the setup open now (R3 S12: `default_space`,
// `labs`). `add(body)` adds it there.
const SpaceContext = createContext('private');

function useAdd() {
  const space = useContext(SpaceContext);
  return (body) => addSource({ space, ...body });
}

/** Where the source goes: only you, or a lab that permits the kind. */
export function SpaceChoice({ kind, value, onChange, name = 'source-space', hideLegend = false }) {
  if (!kind.labs?.length) {
    return kind.lab_refused ? html`<p class="rf-ui-help">${kind.lab_refused}</p>` : null;
  }
  const options = [
    { value: 'private', label: t('sources.space_private'), help: t('sources.space_private_help') },
    ...kind.labs.map((l) => ({ value: l.space, label: l.name, help: t('sources.space_lab_help') })),
  ];
  return html`<${ChoiceGroup} legend=${t('sources.space')} name=${name} value=${value} options=${options}
    onChange=${onChange} hideLegend=${hideLegend} />`;
}

const ABOUT = new Set([
  'folder',
  'obsidian',
  'git',
  'zotero_file',
  'orcid_works',
  'gdrive',
  'gmail',
  'zotero_web',
  'notion',
]);

/** One line about a kind, or nothing for a kind that a later step adds. */
function about(kind) {
  return ABOUT.has(kind) ? t(`sources.about_${kind}`) : '';
}

// Two kinds have the same label on the server ("Zotero library"); a button
// name must be unique, so these two have their own names here.
const NAMED = new Set(['zotero_file', 'zotero_web']);

/** The kinds with a unique label each. */
export function named(kinds) {
  return kinds.map((k) => (NAMED.has(k.kind) ? { ...k, label: t(`sources.name_${k.kind}`) } : k));
}

// A connected kind with no client can be chosen: its setup is the next step.
const missingClient = (k) => !k.available && k.auth === 'oauth';
const choosable = (k) => k.available || missingClient(k);

export function KindGrid({ kinds, chosen, onChoose }) {
  return html`
    <ul class="ag-kinds" aria-label=${t('sources.kinds')}>
      ${kinds.map(
        (k) => html`
        <li key=${k.kind}>
          <button type="button" class="ag-kind" aria-pressed=${chosen === k.kind ? 'true' : 'false'}
            data-ready=${k.available ? undefined : 'false'}
            aria-disabled=${choosable(k) ? undefined : 'true'} aria-labelledby=${`kind-${k.kind}-name`} aria-describedby=${`kind-${k.kind}`}
            onClick=${() => {
              if (choosable(k)) onChoose(chosen === k.kind ? null : k.kind);
            }}>
            <span class="ag-kind-name" id=${`kind-${k.kind}-name`}>${k.label}</span>
            <span class="ag-kind-about" id=${`kind-${k.kind}`}>
              ${k.available ? about(k.kind) : missingClient(k) ? t('sources.not_set_up') : k.unavailable_reason}
            </span>
          </button>
        </li>`,
      )}
    </ul>`;
}

// ------------------------------------------------------------ lab clients

/**
 * The OAuth client of one provider for one lab (lab admins). `lab` is a row
 * of `GET /api/source-settings`. The secret never comes back from the
 * server: a client that is set shows its ID, and the secret field is empty.
 */
export function ClientForm({ lab, provider, onSaved }) {
  const name = PROVIDERS[provider];
  const current = lab.clients[provider];
  const [cid, setCid] = useState(current ? current.client_id : '');
  const [secret, setSecret] = useState('');
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const base = `/api/source-settings/${encodeURIComponent(lab.id)}/clients/${provider}`;
  const after = { invalidate: ['/api/source-settings', '/api/source-kinds'] };
  const save = async () => {
    setSaved('');
    await mutate('PUT', base, { client_id: cid, client_secret: secret }, after);
    setSecret('');
    setSaved(t('sources.client_saved', { provider: name }));
    if (onSaved) onSaved();
  };
  const remove = async () => {
    setSaved('');
    await mutate('DELETE', base, undefined, after);
    setCid('');
    setSecret('');
  };
  return html`
    <div class="ag-client">
      <${Field} id=${`client-id-${provider}`} label=${t('sources.client_id')} help=${t(`sources.client_id_help_${provider}`)}>
        <${TextInput} value=${cid} onInput=${(v) => {
          setCid(v);
          setError('');
        }} spellcheck=${false} autocomplete="off" />
      <//>
      <${Field} id=${`client-secret-${provider}`} label=${t('sources.client_secret')}
        help=${current?.has_secret ? t('sources.client_secret_set') : t('sources.client_secret_help')}>
        <${TextInput} value=${secret} onInput=${setSecret} type="password" spellcheck=${false} autocomplete="off" />
      <//>
      <${ErrorLine} text=${error} />
      <${StatusLine} state="saved" text=${saved} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('sources.client_save', { provider: name })} busyLabel=${t('sources.saving')}
          run=${save} errorTo=${setError} />
        ${
          current &&
          html`
          <${ActionButton} kind="quiet" label=${t('sources.client_remove')} busyLabel=${t('sources.saving')}
            run=${remove} errorTo=${setError} />`
        }
      </div>
    </div>`;
}

/** The setup of a Google or Notion kind with no client: the one next step. */
function NotSetUp({ kind }) {
  const settings = useResource('/api/source-settings', { topics: ['lab'] });
  const data = optional(settings);
  if (!data) return null;
  const name = providerName(kind);
  if (!data.labs.length) return html`<p>${t('sources.no_lab_client', { provider: name })}</p>`;
  const lab = data.labs.find((l) => l.can_edit);
  if (!lab) return html`<p>${t('sources.ask_admin', { provider: name })}</p>`;
  return html`
    <p>${t('sources.client_lead', { provider: name, lab: lab.name })}</p>
    <${Disclosure} kind="details" summary=${t('sources.client_how', { provider: name })}>
      <ol class="ag-steps">
        ${t(`sources.client_steps_${kind.provider}`)
          .split('\n')
          .map((line) => html`<li key=${line}>${line}</li>`)}
      </ol>
    <//>
    <${ClientForm} lab=${lab} provider=${kind.provider} />`;
}

// ------------------------------------------------------------ sign-in

// Wait for one sign-in flow: the `oauth.flow` events reload its state.
function useFlow(flow) {
  const state = useResource(flow ? `/api/accounts/connect/${encodeURIComponent(flow)}` : null, { topics: ['oauth'] });
  return state.data.value;
}

/**
 * Sign in at the provider. With `account`, sign in again to that account
 * (an expired sign-in, or "Choose pages" at Notion). `text` replaces the
 * sentence above the button.
 */
export function SignIn({ kind, account, text, label, onAccount, onCancel }) {
  const [flow, setFlow] = useState(null);
  const [error, setError] = useState('');
  const [calm, setCalm] = useState('');
  const state = useFlow(flow?.flow);
  const name = providerName(kind);
  useEffect(() => {
    if (state && state.state === 'done' && state.account) {
      setFlow(null);
      onAccount(state.account);
    }
  }, [state?.state]);
  const start = async () => {
    setCalm('');
    try {
      setFlow(await api('POST', '/api/accounts/connect', account ? { kind: kind.kind, account } : { kind: kind.kind }));
    } catch (err) {
      // No client for this lab: nobody did wrong; say who can fix it.
      if (err.data && err.data.code === 'client_missing') {
        setCalm(err.message);
        return;
      }
      throw err;
    }
  };
  const cancel = async () => {
    if (flow) await api('POST', `/api/accounts/connect/${encodeURIComponent(flow.flow)}/cancel`).catch(() => null);
    setFlow(null);
    if (onCancel) onCancel();
  };
  if (calm) return html`<${StatusLine} state="paused" text=${calm} />`;
  const failed = state && !['waiting', 'done'].includes(state.state) ? state.error || t('common.failed') : '';
  if (flow && !failed) {
    return html`
      <${StatusLine} state="pending" text=${t('sources.signin_waiting', { provider: name })} />
      <div class="rf-ui-actions">
        <a class="rf-ui-button rf-ui-button--secondary" href=${flow.url} target="_blank" rel="noopener noreferrer">
          ${t('sources.signin_open', { provider: name })}
        </a>
        <${Button} kind="quiet" onClick=${cancel}>${t('common.cancel')}<//>
      </div>`;
  }
  const words =
    text === undefined ? t(account ? 'sources.signin_again_text' : 'sources.signin_text', { provider: name }) : text;
  return html`
    ${words && html`<p>${words}</p>`}
    <${ErrorLine} text=${failed || error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${label || t(account ? 'sources.signin_again' : 'sources.signin', { provider: name })}
        busyLabel=${t('sources.signin_busy')} run=${start} errorTo=${setError} />
    </div>`;
}

// ------------------------------------------------------------ choose what to read

const choicesPath = (account, kind, parent) => {
  const q = new URLSearchParams({ kind: kind.kind });
  if (parent) q.set('parent', parent);
  return `/api/accounts/${encodeURIComponent(account.id)}/choices?${q}`;
};

/** The selection of a Drive source from its `include`. */
export function driveKeys(include) {
  if (!include) return [];
  return [...(include.my_drive ? ['my_drive'] : []), ...(include.shared_drives || []), ...(include.folders || [])];
}

// One level of the Drive tree. A folder opens on request; nothing is chosen
// at the start.
function DriveLevel({ kind, account, items, value, onToggle, types, depth }) {
  const [open, setOpen] = useState({}); // id -> list of children, or 'loading'
  const [error, setError] = useState('');
  const expand = async (item) => {
    if (open[item.id]) {
      setOpen({ ...open, [item.id]: undefined });
      return;
    }
    setOpen({ ...open, [item.id]: 'loading' });
    try {
      const out = await api('GET', choicesPath(account, kind, item.id));
      for (const child of out.items) types.current[child.id] = child.type || 'folder';
      setOpen((o) => ({ ...o, [item.id]: out.items }));
    } catch (err) {
      setError(err.message);
      setOpen((o) => ({ ...o, [item.id]: undefined }));
    }
  };
  return html`
    <ul class="ag-tree" role=${depth ? 'group' : undefined} aria-label=${depth ? undefined : t('sources.drive_choose')}>
      ${items.map((item) => {
        const id = `drive-${item.id}`;
        const kids = open[item.id];
        return html`
          <li key=${item.id}>
            <div class="ag-tree-row">
              ${
                item.has_children !== false
                  ? html`<button type="button" class="ag-tree-open" aria-expanded=${kids && kids !== 'loading' ? 'true' : 'false'}
                    aria-label=${t('sources.drive_open', { name: item.name })} onClick=${() => expand(item)}>
                    <span class="ag-disclosure-sign" aria-hidden="true"></span>
                  </button>`
                  : html`<span class="ag-tree-open" aria-hidden="true"></span>`
              }
              <label class="ag-check" for=${id}>
                <input type="checkbox" id=${id} checked=${value.includes(item.id)} onChange=${() => onToggle(item.id)} />
                <span>${item.name}</span>
              </label>
            </div>
            ${kids === 'loading' && html`<p class="rf-ui-help ag-tree-wait" role="status">${t('sources.reading_folders')}</p>`}
            ${
              Array.isArray(kids) &&
              (kids.length
                ? html`<${DriveLevel} kind=${kind} account=${account} items=${kids} value=${value}
                  onToggle=${onToggle} types=${types} depth=${depth + 1} />`
                : html`<p class="rf-ui-help ag-tree-wait">${t('sources.no_folders')}</p>`)
            }
          </li>`;
      })}
    </ul>
    <${ErrorLine} text=${error} />`;
}

/** The Drive folder tree. `value` is a list of IDs; `submit(include)` saves it. */
export function DriveChoice({ kind, account, value: start = [], action, submit }) {
  const choices = useResource(choicesPath(account, kind));
  const [keys, setKeys] = useState(start);
  const [error, setError] = useState('');
  const types = useRef({});
  const top = choices.data.value?.items || [];
  for (const item of top) types.current[item.id] = item.type;
  if (choices.error.value) return html`<${ErrorLine} text=${choices.error.value.message} />`;
  if (!choices.data.value)
    return html`<p class="ag-empty" role="status">${t('sources.reading_choices', { provider: providerName(kind) })}</p>`;
  const toggle = (id) => setKeys(keys.includes(id) ? keys.filter((k) => k !== id) : [...keys, id]);
  const run = async () => {
    if (!keys.length) throw new Error(t('sources.choose_one'));
    const type = (id) => types.current[id] || 'folder';
    await submit({
      my_drive: keys.includes('my_drive'),
      shared_drives: keys.filter((k) => type(k) === 'shared_drive'),
      folders: keys.filter((k) => type(k) === 'folder'),
    });
  };
  return html`
    <fieldset class="rf-ui-choices ag-drive">
      <legend>${t('sources.drive_choose')}</legend>
      <${DriveLevel} kind=${kind} account=${account} items=${top} value=${keys} onToggle=${toggle} types=${types} depth=${0} />
    </fieldset>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${action} busyLabel=${t('sources.saving')} run=${run} errorTo=${setError} />
    </div>`;
}

const MODES = ['mine', 'labels', 'all'];

/** Gmail: which mail, with the estimate before the start. */
export function MailChoice({ kind, account, value: start, action, submit }) {
  const choices = useResource(choicesPath(account, kind));
  const [mode, setMode] = useState(start?.mode || 'mine');
  const [labels, setLabels] = useState(start?.labels || []);
  const [estimate, setEstimate] = useState(null);
  const [error, setError] = useState('');
  const filter = mode === 'labels' ? { mode, labels } : { mode };
  const key = JSON.stringify(filter);
  useEffect(() => {
    let live = true;
    setEstimate(null);
    if (mode === 'labels' && !labels.length) return undefined;
    const timer = setTimeout(async () => {
      const out = await api('POST', '/api/sources/preview', { kind: kind.kind, account: account.id, filter }).catch(
        () => null,
      );
      if (live) setEstimate(out);
    }, 300);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [key]);
  const data = choices.data.value;
  if (choices.error.value) return html`<${ErrorLine} text=${choices.error.value.message} />`;
  if (!data) return html`<p class="ag-empty" role="status">${t('sources.reading_labels')}</p>`;
  const run = async () => {
    if (mode === 'labels' && !labels.length) throw new Error(t('sources.choose_label'));
    await submit(filter);
  };
  const options = MODES.map((m) => ({ value: m, label: t(`sources.mail_${m}`), help: t(`sources.mail_${m}_help`) }));
  return html`
    <${ChoiceGroup} legend=${t('sources.mail_choose')} name="mail-mode" value=${mode} options=${options} onChange=${setMode} />
    ${
      mode === 'labels' &&
      (data.labels.length
        ? html`<${CheckList} legend=${t('sources.mail_labels')} name="mail-labels" value=${labels} onChange=${setLabels}
          items=${data.labels.map((l) => ({ value: l.name, label: l.name }))} />`
        : html`<p class="rf-ui-help">${t('sources.mail_no_labels')}</p>`)
    }
    <p class="rf-ui-help ag-estimate" role="status">
      ${
        estimate && Number.isFinite(estimate.estimate)
          ? t('sources.mail_estimate', {
              n: estimate.estimate.toLocaleString('en-GB'),
              of: (estimate.of || 0).toLocaleString('en-GB'),
            })
          : ''
      }
    </p>
    <p class="rf-ui-help">${t('sources.mail_left_out')}</p>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${action} busyLabel=${t('sources.saving')} run=${run} errorTo=${setError} />
    </div>`;
}

/** Notion: the pages that the person chose at Notion, and "Choose pages". */
export function PagesChoice({ kind, account, action, submit }) {
  const choices = useResource(choicesPath(account, kind), { topics: ['account'] });
  const [again, setAgain] = useState(false);
  const [error, setError] = useState('');
  const data = choices.data.value;
  if (choices.error.value) return html`<${ErrorLine} text=${choices.error.value.message} />`;
  if (!data) return html`<p class="ag-empty" role="status">${t('sources.reading_pages')}</p>`;
  if (again) {
    return html`<${SignIn} kind=${kind} account=${account.id} text=${t('sources.pages_again_text')}
      label=${t('sources.pages_choose')} onAccount=${() => {
        setAgain(false);
        choices.reload();
      }} onCancel=${() => setAgain(false)} />`;
  }
  return html`
    ${
      data.pages.length
        ? html`
        <p class="ag-pages-head">${t('sources.pages', { n: data.pages.length })}</p>
        <ul class="ag-plain ag-pages">${data.pages.slice(0, 12).map((p) => html`<li key=${p.id}>${p.title}</li>`)}</ul>
        ${data.pages.length > 12 && html`<p class="rf-ui-help">${t('sources.pages_more', { n: data.pages.length - 12 })}</p>`}`
        : html`<p>${t('sources.pages_none')}</p>`
    }
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      ${
        submit &&
        data.pages.length > 0 &&
        html`
        <${ActionButton} label=${action} busyLabel=${t('sources.saving')} run=${() => submit(null)} errorTo=${setError} />`
      }
      <${Button} kind=${submit && data.pages.length ? 'quiet' : 'secondary'} onClick=${() => setAgain(true)}>${t('sources.pages_choose')}<//>
    </div>`;
}

function SimpleAdd({ kind, body, text, onDone }) {
  const add = useAdd();
  const [error, setError] = useState('');
  return html`
    ${text && html`<p>${text}</p>`}
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('sources.add_kind', { kind: kind.label })} busyLabel=${t('sources.adding')}
        run=${async () => onDone(await add(body))} errorTo=${setError} />
    </div>`;
}

function Cloud({ kind, onDone }) {
  const accounts = useResource('/api/accounts', { topics: ['account', 'oauth'] });
  const add = useAdd();
  const [fresh, setFresh] = useState(null);
  if (!accounts.data.value && !accounts.error.value) return null;
  const list = accounts.data.value?.accounts || [];
  const account = fresh || list.find((a) => a.provider === kind.provider && a.status === 'ok');
  if (!account) {
    return html`<${SignIn} kind=${kind} onAccount=${(a) => {
      setFresh(a);
      accounts.reload();
    }} />`;
  }
  const signed = html`<p class="rf-ui-help">${t('sources.signed_in', { account: account.label })}</p>`;
  const label = t('sources.add_kind', { kind: kind.label });
  const base = { kind: kind.kind, account: account.id };
  // An account that lacks the scope of this kind signs in again to add it.
  const run = async (body) => {
    try {
      onDone(await add(body));
    } catch (err) {
      if (err.data && err.data.code === 'scope_missing') {
        setFresh(null);
        await accounts.reload();
      }
      throw err;
    }
  };
  if (kind.choose === 'folders') {
    return html`${signed}<${DriveChoice} kind=${kind} account=${account} action=${label}
      submit=${(include) => run({ ...base, include })} />`;
  }
  if (kind.choose === 'filter') {
    return html`${signed}<${MailChoice} kind=${kind} account=${account} action=${label}
      submit=${(filter) => run({ ...base, filter })} />`;
  }
  if (kind.choose === 'provider') {
    return html`${signed}<${PagesChoice} kind=${kind} account=${account} action=${label} submit=${() => run(base)} />`;
  }
  return html`${signed}<${SimpleAdd} kind=${kind} body=${base} onDone=${onDone} />`;
}

function KeyAdd({ kind, onDone }) {
  const add = useAdd();
  const [key, setKey] = useState('');
  const [error, setError] = useState('');
  const submit = async () => {
    const out = await api('POST', '/api/accounts/key', { kind: kind.kind, key });
    onDone(await add({ kind: kind.kind, account: out.account.id }));
  };
  return html`
    <${Field} id="source-key" label=${t('sources.key_label', { provider: providerName(kind) })} help=${t('sources.key_help')}>
      <${TextInput} value=${key} onInput=${setKey} type="password" autocomplete="off" spellcheck=${false} />
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('sources.add_kind', { kind: kind.label })} busyLabel=${t('sources.adding')} run=${submit} errorTo=${setError} />
    </div>`;
}

function PathAdd({ kind, onDone }) {
  const add = useAdd();
  const [path, setPath] = useState('');
  const [error, setError] = useState('');
  return html`
    <${Field} id="zotero-path" label=${t('sources.zotero_label')} help=${t('sources.zotero_help')}>
      <${TextInput} value=${path} onInput=${setPath} placeholder=${t('sources.zotero_placeholder')} spellcheck=${false} />
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('sources.add_kind', { kind: kind.label })} busyLabel=${t('sources.adding')}
        run=${async () => onDone(await add({ kind: kind.kind, path }))} errorTo=${setError} />
    </div>`;
}

function PickFolder({ kind, onDone, onCancel }) {
  const add = useAdd();
  return html`<${FolderPicker} kind=${kind.kind} onPick=${async (path) => onDone(await add({ kind: kind.kind, path }))} onCancel=${onCancel} />`;
}

/** The setup of one kind, below the grid. `onDone(result)` gets the answer of `POST /api/sources`. */
export function Setup({ kind, onDone, onCancel }) {
  const [space, setSpace] = useState(kind.default_space || 'private');
  const titleRef = useRef(null);
  useEffect(() => {
    const el = titleRef.current;
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      el.focus({ preventScroll: true });
    }
  }, [kind.kind]);
  let body;
  if (missingClient(kind)) {
    body = html`<${NotSetUp} kind=${kind} />`;
  } else if (PICK.has(kind.kind)) {
    body = html`<${PickFolder} kind=${kind} onDone=${onDone} onCancel=${onCancel} />`;
  } else if (kind.kind === 'zotero_file') {
    body = html`<${PathAdd} kind=${kind} onDone=${onDone} />`;
  } else if (kind.auth === 'oauth') {
    body = html`<${Cloud} kind=${kind} onDone=${onDone} />`;
  } else if (kind.auth === 'api_key') {
    body = html`<${KeyAdd} kind=${kind} onDone=${onDone} />`;
  } else {
    body = html`<${SimpleAdd} kind=${kind} text=${about(kind.kind)} body=${{ kind: kind.kind }} onDone=${onDone} />`;
  }
  return html`
    <section class="ag-setup" aria-labelledby="setup-title">
      <h2 class="ag-setup-title" id="setup-title" tabindex="-1" ref=${titleRef}>${kind.label}</h2>
      ${kind.available && html`<${SpaceChoice} kind=${kind} value=${space} onChange=${setSpace} />`}
      <${SpaceContext.Provider} value=${space}>${body}<//>
    </section>`;
}
