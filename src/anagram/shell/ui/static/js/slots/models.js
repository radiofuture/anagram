// Slot view `account.sections` of track R4 (step 11b): the model of this
// person. Which model reads the items and which answers the questions, the
// models with their test, key, and sources, the spend limit of a cloud
// model, and the form to add a model (`parts/model_form.js`).
//
// The default needs no choice: when Ollama runs on this computer, the server
// selects it (`GET /api/models` applies the local default). Routes:
// `GET /api/models`, `PUT /api/models/profiles/{id}`, `PUT|DELETE
// /api/models/profiles/{id}/key`, `POST /api/models/profiles/{id}/test`,
// `PUT /api/models/use`, `PUT /api/models/budget`, `PUT
// /api/sources/{id}/recipients`. Words: `copy/models.json`. No id shows.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { fmtDate } from '../core/format.js';
import { invalidate, mutate, optional, useResource } from '../core/resource.js';
import { provide } from '../core/slots.js';
import {
  ActionButton,
  Button,
  CheckList,
  Disclosure,
  ErrorLine,
  Facts,
  Field,
  Row,
  RowList,
  Section,
  StatusLine,
  TextInput,
} from '../components/index.js';
import { ModelForm } from '../parts/model_form.js';

const PATH = '/api/models';
const AFTER = [PATH, '/api/ask/setup'];
const NONE = '';

const put = (path, body) => mutate('PUT', path, body, { invalidate: AFTER });

/** The name of a model for people: its label, and "from your lab" for a lab model. */
const nameOf = (p) => (p.origin === 'member' ? p.label : t('models.from_lab', { label: p.label }));

/** Where the text goes: this computer, or the party that reads it. */
const whereText = (p) => {
  if (!p.external) return t('models.here');
  return p.provider === 'openai_compatible' ? p.model : p.recipient;
};

// ------------------------------------------------------------ the two uses

async function use(tasks, pid, acknowledged) {
  for (const task of tasks) await setUse(task, pid, acknowledged);
  await invalidate(AFTER);
}

function setUse(task, profile, acknowledged) {
  return mutate('PUT', '/api/models/use', { task, profile, acknowledged }, {});
}

const TASKS = { reads: ['understand'], answers: ['ask', 'draft'] };

function UseSelect({ id, label, value, profiles, onPick }) {
  return html`
    <${Field} id=${id} label=${label}>
      <select class="rf-ui-input" id=${id} value=${value || NONE} onChange=${(e) => onPick(e.currentTarget.value || null)}>
        ${profiles.map((p) => html`<option key=${p.id} value=${p.id}>${nameOf(p)}</option>`)}
        <option value=${NONE}>${t('models.none')}</option>
      </select>
    <//>`;
}

function Uses({ data }) {
  const [ask, setAsk] = useState(null); // {role, p}: an outside model waits for a yes
  const [error, setError] = useState('');
  const byId = Object.fromEntries(data.profiles.map((p) => [p.id, p]));
  const now = { reads: data.use.understand, answers: data.use.ask };
  const pick = async (role, pid) => {
    setError('');
    setAsk(null);
    const p = pid && byId[pid];
    if (p?.external) {
      setAsk({ role, p });
      return;
    }
    try {
      await use(TASKS[role], pid, false);
      announce(t('models.saved'));
    } catch (err) {
      setError(err.message);
    }
  };
  const yes = async () => {
    await use(TASKS[ask.role], ask.p.id, true);
    setAsk(null);
    announce(t('models.saved'));
  };
  const shown = (role) => (ask && ask.role === role ? ask.p.id : now[role]);
  return html`
    <div class="ag-model-uses">
      <${UseSelect} id="model-reads" label=${t('models.reads')} value=${shown('reads')} profiles=${data.profiles}
        onPick=${(v) => pick('reads', v)} />
      <${UseSelect} id="model-answers" label=${t('models.answers')} value=${shown('answers')} profiles=${data.profiles}
        onPick=${(v) => pick('answers', v)} />
    </div>
    ${
      ask &&
      html`
      <div class="ag-model-ask ag-m-enter">
        <p>${ask.p.sentence}</p>
        <div class="rf-ui-actions">
          <${ActionButton} label=${t('models.use', { name: ask.p.label })} busyLabel=${t('models.saving')} run=${yes} errorTo=${setError} />
          <${Button} kind="quiet" onClick=${() => setAsk(null)}>${t('models.keep')}<//>
        </div>
      </div>`
    }
    <${ErrorLine} text=${error} />`;
}

// ------------------------------------------------------------- one model

function Key({ p }) {
  const [key, setKey] = useState('');
  const [error, setError] = useState('');
  const path = `${PATH}/profiles/${encodeURIComponent(p.id)}/key`;
  if (p.has_key) {
    return html`
      <p class="ag-model-note">${t('models.key_kept')}
        ${' '}<${ActionButton} kind="quiet" label=${t('models.key_remove')} busyLabel=${t('models.saving')}
          run=${() => mutate('DELETE', path, undefined, { invalidate: AFTER })} errorTo=${setError} /></p>
      <${ErrorLine} text=${error} />`;
  }
  const save = async () => {
    await mutate('PUT', path, { key }, { invalidate: AFTER });
    setKey('');
    announce(t('models.key_saved'));
  };
  const form = html`
    <${Field} id=${`key-${p.id}`} label=${p.needs_key ? t('models.key') : t('models.key_optional')} help=${t('models.key_help')}>
      <${TextInput} value=${key} onInput=${setKey} type="password" spellcheck=${false} autocomplete="off" />
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${t('models.key_save')} busyLabel=${t('models.saving')} run=${save}
        errorTo=${setError} disabled=${!key.trim()} />
    </div>`;
  return p.needs_key ? form : html`<${Disclosure} kind="add" summary=${t('models.key_add')}>${form}<//>`;
}

function Sources({ p, sources }) {
  const [error, setError] = useState('');
  const open = sources.filter((s) => s.space === 'private' || p.lab_allows);
  if (!open.length) return html`<p class="ag-model-note">${t('models.sources_none')}</p>`;
  const value = open.filter((s) => s.allow.includes(p.id)).map((s) => s.id);
  const change = async (next) => {
    setError('');
    try {
      for (const s of open) {
        const on = next.includes(s.id);
        if (on === s.allow.includes(p.id)) continue;
        const allow = on ? [...s.allow, p.id] : s.allow.filter((x) => x !== p.id);
        await mutate(
          'PUT',
          `/api/sources/${encodeURIComponent(s.id)}/recipients`,
          { allow: allow.map((x) => `model:${x}`) },
          {},
        );
      }
      await invalidate(AFTER);
    } catch (err) {
      setError(err.message);
    }
  };
  return html`
    <${CheckList} legend=${t('models.sources', { name: p.label })} name=${`src-${p.id}`} value=${value}
      items=${open.map((s) => ({ value: s.id, label: s.label }))} onChange=${change} />
    ${
      p.lab_allows === false &&
      sources.some((s) => s.space !== 'private') &&
      html`<p class="rf-ui-help">${t('models.lab_refuses')}</p>`
    }
    <${ErrorLine} text=${error} />`;
}

function Test({ p }) {
  const [out, setOut] = useState(null);
  const run = async () => {
    setOut({ state: 'pending', text: t('models.testing') });
    const got = await mutate('POST', `${PATH}/profiles/${encodeURIComponent(p.id)}/test`, undefined, {
      invalidate: AFTER,
    });
    setOut(got.ok ? { state: 'saved', text: t('models.test_ok') } : { state: 'error', text: got.message });
  };
  return html`
    <${ActionButton} kind="secondary" label=${t('models.test')} busyLabel=${t('models.testing')} run=${run}
      errorTo=${(m) => m && setOut({ state: 'error', text: m })} />
    <${StatusLine} ...${out || {}} />`;
}

function Model({ p, data }) {
  const [error, setError] = useState('');
  const keyed = p.needs_key || p.provider === 'openai_compatible';
  const remove = () =>
    mutate('DELETE', `${PATH}/profiles/${encodeURIComponent(p.id)}`, undefined, { invalidate: AFTER });
  return html`
    <${Row} title=${nameOf(p)} meta=${whereText(p)}>
      <div class="ag-model-more">
        ${keyed && html`<${Key} p=${p} />`}
        ${p.external && html`<${Sources} p=${p} sources=${data.sources} />`}
        <div class="rf-ui-actions ag-model-actions">
          <${Test} p=${p} />
          ${
            p.origin === 'member' &&
            html`
            <${ActionButton} kind="quiet" label=${t('models.remove')} busyLabel=${t('models.removing')} run=${remove} errorTo=${setError} />`
          }
        </div>
        <${ErrorLine} text=${error} />
      </div>
    <//>`;
}

// ------------------------------------------------------------ spend limit

function Spend({ budget }) {
  const [limit, setLimit] = useState(budget ? budget.budget_usd : '10');
  const [until, setUntil] = useState(
    budget ? budget.expires : new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10),
  );
  const [error, setError] = useState('');
  const save = () => put(`${PATH}/budget`, { budget_usd: limit.trim(), expires: until });
  const form = html`
    <div class="ag-model-pair">
      <${Field} id="spend-limit" label=${t('models.limit')}>
        <${TextInput} value=${limit} onInput=${setLimit} inputmode="decimal" autocomplete="off" />
      <//>
      <${Field} id="spend-until" label=${t('models.until')}>
        <${TextInput} value=${until} onInput=${setUntil} type="date" />
      <//>
    </div>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${t('models.limit_save')} busyLabel=${t('models.saving')} run=${save} errorTo=${setError} />
    </div>`;
  if (!budget) {
    return html`
      <h3 class="ag-subtitle">${t('models.spend')}</h3>
      <p class="rf-ui-help">${t('models.spend_help')}</p>
      ${form}`;
  }
  return html`
    <h3 class="ag-subtitle">${t('models.spend')}</h3>
    <${Facts} rows=${[
      [
        t('models.spent'),
        t('models.spent_of', {
          spent: budget.spent_usd || '0',
          limit: budget.budget_usd,
          date: fmtDate(budget.expires),
        }),
      ],
    ]} />
    <${Disclosure} kind="add" summary=${t('models.limit_change')}>${form}<//>`;
}

// ------------------------------------------------------------------ add

function Add({ data, onAdded }) {
  const paidOpen = Boolean(data.budget?.open);
  const add = async ({ profile, key, budget }) => {
    const out = await mutate('PUT', `${PATH}/profiles/new`, profile, {});
    const pid = out.saved;
    if (key) await mutate('PUT', `${PATH}/profiles/${encodeURIComponent(pid)}/key`, { key }, {});
    if (budget) await mutate('PUT', `${PATH}/budget`, budget, {});
    // The button says "Use this model", and the line above it says what leaves.
    for (const task of ['understand', 'ask', 'draft']) await setUse(task, pid, true);
    await invalidate(AFTER);
    announce(t('models.added', { name: profile.label }));
    onAdded();
  };
  const taken = data.profiles.filter((p) => p.provider === 'ollama').map((p) => p.model);
  return html`
    <${ModelForm} ollama=${data.ollama} budget=${!paidOpen} taken=${taken} onSubmit=${add}
      submitLabel=${t('models.add_use')} busyLabel=${t('models.adding')} onLook=${() => invalidate([PATH])} />`;
}

// --------------------------------------------------------------- section

// Only a fault is an error line. No model is a normal state: the app works
// with rules, so it is a plain sentence with its one next step (`NoModel`).
const FAULTS = ['unreachable', 'budget_reached', 'weak_model'];

function lead(data) {
  const s = data.state;
  if (s.state === 'ready' || s.state === 'no_model') return null;
  return { state: FAULTS.includes(s.state) ? 'error' : 'outdated', text: s.message };
}

/** The next step moves the focus to the first choice: the select of the
 *  model that reads, or the place where a new model runs. */
function NoModel({ s, chosen }) {
  const choose = () => {
    const to = document.querySelector(chosen ? '#model-reads' : 'input[name="model-where"]:checked');
    if (to) to.focus();
  };
  return html`
    <div class="ag-model-none">
      <p>${s.message}</p>
      <${Button} kind="quiet" onClick=${choose}>${s.next}<//>
    </div>`;
}

function Models() {
  const res = useResource(PATH, { topics: [['models', 'state'].join('.'), 'source.added', 'source.removed'] });
  const data = optional(res);
  const [n, setN] = useState(0); // a new form after each add
  if (!data) return null;
  const paid = data.profiles.some((p) => p.paid);
  const l = lead(data);
  const reads = data.profiles.find((p) => p.id === data.use.understand);
  return html`
    <${Section} id="models-title" title=${t('models.title')}>
      ${l && html`<${StatusLine} ...${l} />`}
      ${data.state.state === 'no_model' && html`<${NoModel} s=${data.state} chosen=${data.profiles.length > 0} />`}
      ${data.profiles.length > 0 && html`<${Uses} data=${data} />`}
      ${reads && !reads.external && html`<p class="ag-model-leaves">${reads.sentence}</p>`}
      ${
        data.profiles.length > 0 &&
        html`
        <${RowList} items=${data.profiles} keyOf=${(p) => p.id} label=${t('models.list')}
          render=${(p) => html`<${Model} p=${p} data=${data} />`} />`
      }
      ${paid && html`<${Spend} key=${data.budget ? `${data.budget.budget_usd}-${data.budget.expires}` : 'none'} budget=${data.budget} />`}
      ${
        data.profiles.length
          ? html`<${Disclosure} key=${n} kind="add" summary=${t('models.add')}><${Add} key=${n} data=${data} onAdded=${() => setN(n + 1)} /><//>`
          : html`<${Add} key=${n} data=${data} onAdded=${() => setN(n + 1)} />`
      }
    <//>`;
}

provide('account.sections', { order: 20, View: Models });
