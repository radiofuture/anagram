// Slot view `account.sections` of track R4 (step 16), agent grant v2:
// Assistant access. The person's own AI assistant (for example Claude
// Desktop) can search the library and read items, and, if the person turns
// it on, propose lines for matching. A proposal waits here until the
// person approves or declines it: an assistant cannot approve its own
// proposal. Off until the person adds an assistant; each assistant has its
// own places, class ("runs on this computer only"), end date, setup text,
// and a list of what it read. A lab space shows only when the lab permits
// assistants (and cloud assistants, for a cloud assistant). Routes:
// `GET`/`POST /api/assistant`, `PUT`/`DELETE /api/assistant/{id}`,
// `POST /api/assistant/{id}/http`, `POST /api/assistant/proposals/{id}`.
// Words: `copy/assistant.json`. No id or path shows.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { fmtDate, fmtTime } from '../core/format.js';
import { api } from '../core/api.js';
import { invalidate, mutate, optional, useResource } from '../core/resource.js';
import { provide } from '../core/slots.js';
import {
  ActionButton,
  Button,
  Check,
  CheckList,
  ChoiceGroup,
  CopyField,
  Disclosure,
  ErrorLine,
  Field,
  Row,
  RowList,
  Section,
  Sheet,
  TextInput,
  openSheet,
} from '../components/index.js';

const PATH = '/api/assistant';
const DEFAULT_NAME = () => t('assistant.default_name');
const ACT = 'act.lines_propose';

function placeItems(spaces, cls) {
  return spaces.map((s) => {
    const open = cls === 'local' ? s.allowed : s.allowed_cloud;
    return {
      value: s.id,
      label: s.id === 'private' ? t('assistant.place_private') : s.label || t('assistant.place_lab'),
      help: open ? null : t(s.allowed ? 'assistant.lab_closed_cloud' : 'assistant.lab_closed'),
      fixed: !open,
    };
  });
}

function placesLine(row, spaces) {
  return row.spaces
    .map((id) => {
      if (id === 'private') return t('assistant.place_private');
      const s = spaces.find((x) => x.id === id);
      return s?.label || t('assistant.place_lab');
    })
    .join(', ');
}

function classOptions() {
  return [
    { value: 'cloud', label: t('assistant.class_cloud'), help: t('assistant.class_cloud_help') },
    { value: 'local', label: t('assistant.class_local'), help: t('assistant.class_local_help') },
  ];
}

/** The setup text for one assistant: copy it into the settings of the assistant. */
function Setup({ row, open }) {
  const [http, setHttp] = useState(null);
  const [error, setError] = useState('');
  const makeKey = async () => {
    setHttp(await api('POST', `${PATH}/${encodeURIComponent(row.id)}/http`));
  };
  return html`
    <${Disclosure} summary=${t('assistant.setup_title')} open=${open} kind="add">
      <p class="rf-ui-help">${t('assistant.setup_help', { name: row.name })}</p>
      <${CopyField} id=${`assistant-setup-${row.id}`} label=${t('assistant.setup_label')} value=${row.setup} rows=${6} />
      <${Disclosure} summary=${t('assistant.http_title')}>
        <p class="rf-ui-help">${t('assistant.http_help')}</p>
        ${
          http
            ? html`
            <p class="rf-ui-help">${t('assistant.http_once')}</p>
            <${CopyField} id=${`assistant-http-${row.id}`} label=${t('assistant.http_label')} value=${http.setup} rows=${7} />
            <${CopyField} id=${`assistant-http-cmd-${row.id}`} label=${t('assistant.http_command')} value=${http.command} rows=${2} />`
            : html`
            <div class="rf-ui-actions">
              <${ActionButton} kind="quiet" label=${t(row.http ? 'assistant.http_new' : 'assistant.http_make')}
                busyLabel=${t('assistant.http_making')} run=${makeKey} errorTo=${setError} />
            </div>`
        }
        <${ErrorLine} text=${error} />
      <//>
    <//>`;
}

function Places({ row, spaces }) {
  const [chosen, setChosen] = useState(row.spaces);
  const [error, setError] = useState('');
  const items = placeItems(spaces, row.recipient_class);
  if (items.filter((i) => !i.fixed).length < 2) return null;
  const save = (value) => {
    setChosen(value);
    setError('');
    mutate('PUT', `${PATH}/${encodeURIComponent(row.id)}`, { spaces: value }, { invalidate: [PATH] }).catch((err) => {
      setChosen(row.spaces);
      setError(err.message);
    });
  };
  return html`
    <${CheckList} legend=${t('assistant.places')} name=${`assistant-places-${row.id}`} items=${items}
      value=${chosen} onChange=${save} />
    <${ErrorLine} text=${error} />`;
}

function Proposals({ row }) {
  const [on, setOn] = useState(row.tools.includes(ACT));
  const [error, setError] = useState('');
  const save = (value) => {
    setOn(value);
    setError('');
    mutate('PUT', `${PATH}/${encodeURIComponent(row.id)}`, { acts: value }, { invalidate: [PATH] }).catch((err) => {
      setOn(!value);
      setError(err.message);
    });
  };
  return html`
    <${Check} id=${`assistant-acts-${row.id}`} label=${t('assistant.acts')} checked=${on} onChange=${save} />
    <${ErrorLine} text=${error} />`;
}

/** What this assistant read: the newest log rows. */
function Reads({ row }) {
  if (!row.reads.length) return null;
  return html`
    <${Disclosure} summary=${t('assistant.reads_title')}>
      <ul class="ag-assistant-reads">
        ${row.reads.map(
          (r, n) => html`
          <li key=${n}>${t('assistant.read_line', { what: r.what, source: r.source || t('assistant.place_private'), time: fmtTime(r.at) })}</li>`,
        )}
      </ul>
    <//>`;
}

function ConfirmStop({ name, close }) {
  return html`
    <${Sheet} title=${t('assistant.stop_confirm_title', { name })}>
      <p>${t('assistant.stop_confirm', { name })}</p>
      <div class="rf-ui-actions">
        <${Button} kind="danger" onClick=${() => close(true)}>${t('assistant.stop_confirm_action')}<//>
        <${Button} kind="quiet" onClick=${() => close(false)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

function Extend({ row }) {
  const [expires, setExpires] = useState('');
  const [error, setError] = useState('');
  if (row.state !== 'expired') return null;
  const save = async () => {
    await mutate(
      'PUT',
      `${PATH}/${encodeURIComponent(row.id)}`,
      { expires: expires || null },
      { invalidate: [PATH] },
    );
    setExpires('');
  };
  return html`
    <${Field} id=${`assistant-extend-${row.id}`} label=${t('assistant.extend_label')} help=${t('assistant.expires_help')}>
      <${TextInput} type="date" value=${expires} onInput=${setExpires} />
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} kind="secondary" label=${t('assistant.extend_action')} busyLabel=${t('assistant.extend_busy')}
        run=${save} errorTo=${setError} />
    </div>`;
}

function Assistant({ row, spaces, fresh }) {
  const [error, setError] = useState('');
  const stop = async () => {
    const yes = await openSheet(ConfirmStop, { name: row.name });
    if (!yes) return;
    await mutate('DELETE', `${PATH}/${encodeURIComponent(row.id)}`, null, { invalidate: [PATH] });
  };
  const meta = [
    placesLine(row, spaces),
    t(row.recipient_class === 'local' ? 'assistant.class_local' : 'assistant.class_cloud'),
    row.state === 'expired'
      ? t('assistant.expired')
      : row.expires
        ? t('assistant.ends', { day: fmtDate(row.expires) })
        : t('assistant.no_end'),
    row.last_used ? t('assistant.last_used', { time: fmtTime(row.last_used) }) : t('assistant.not_used'),
  ].join('. ');
  return html`
    <${Row} title=${row.name} meta=${meta}
      action=${html`<${ActionButton} kind="quiet" label=${t('assistant.stop')} busyLabel=${t('assistant.stopping')}
        run=${stop} errorTo=${setError} aria-label=${t('assistant.stop_name', { name: row.name })} />`}>
      <${ErrorLine} text=${error} />
      <${Extend} row=${row} />
      <${Places} row=${row} spaces=${spaces} />
      <${Proposals} row=${row} />
      <${Setup} row=${row} open=${fresh} />
      <${Reads} row=${row} />
    <//>`;
}

/** One proposal of an assistant: the exact lines and what the approval causes. */
function Proposal({ entry }) {
  const [error, setError] = useState('');
  const decide = (action) => () =>
    mutate('POST', `${PATH}/proposals/${encodeURIComponent(entry.id)}`, { action }, { invalidate: [PATH] });
  const p = entry.payload;
  return html`
    <${Row} title=${t('assistant.proposal_title', { name: entry.grant_name })}
      meta=${fmtTime(entry.created_at)}>
      <dl class="ag-assistant-proposal">
        ${
          p.offers.length > 0 &&
          html`<dt>${t('assistant.proposal_offers')}</dt>
          <dd><ul>${p.offers.map((x, n) => html`<li key=${n}>${x}</li>`)}</ul></dd>`
        }
        ${
          p.wants.length > 0 &&
          html`<dt>${t('assistant.proposal_wants')}</dt>
          <dd><ul>${p.wants.map((x, n) => html`<li key=${n}>${x}</li>`)}</ul></dd>`
        }
      </dl>
      <p class="rf-ui-help">${entry.disclosure}</p>
      ${entry.flags.length > 0 && html`<p class="rf-ui-help ag-assistant-flag">${t('assistant.proposal_flag')}</p>`}
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('assistant.approve')} busyLabel=${t('assistant.approving')}
          run=${decide('approve')} errorTo=${setError} />
        <${ActionButton} kind="quiet" label=${t('assistant.decline')} busyLabel=${t('assistant.declining')}
          run=${decide('decline')} errorTo=${setError} />
      </div>
    <//>`;
}

function Add({ spaces, onAdded }) {
  const [name, setName] = useState(DEFAULT_NAME());
  const [cls, setCls] = useState('cloud');
  const items = placeItems(spaces, cls);
  const [chosen, setChosen] = useState(['private']);
  const [acts, setActs] = useState(false);
  const [expires, setExpires] = useState('');
  const [error, setError] = useState('');
  const shown = (name || '').trim() || DEFAULT_NAME();
  const open = new Set(items.filter((i) => !i.fixed).map((i) => i.value));
  const places = chosen.filter((v) => open.has(v));
  const add = async () => {
    // The new row must know that it is new when it mounts: its setup text opens.
    const out = await api('POST', PATH, {
      name,
      spaces: places,
      recipient_class: cls,
      acts,
      expires: expires || null,
    });
    onAdded(out.added);
    await invalidate([PATH]);
  };
  return html`
    <${Field} id="assistant-name" label=${t('assistant.name')}>
      <${TextInput} value=${name} onInput=${setName} />
    <//>
    <${ChoiceGroup} legend=${t('assistant.class_legend')} name="assistant-new-class" value=${cls}
      options=${classOptions()} onChange=${setCls} />
    ${
      items.length > 1 &&
      html`
      <${CheckList} legend=${t('assistant.places')} name="assistant-new-places" items=${items}
        value=${places} onChange=${setChosen} />`
    }
    <${Disclosure} summary=${t('assistant.more_options')}>
      <${Check} id="assistant-new-acts" label=${t('assistant.acts')} checked=${acts} onChange=${setActs} />
      <${Field} id="assistant-expires" label=${t('assistant.expires')} help=${t('assistant.expires_help')}>
        <${TextInput} type="date" value=${expires} onInput=${setExpires} />
      <//>
    <//>
    <p class="rf-ui-help ag-assistant-consent">${t(cls === 'local' ? 'assistant.consent_local' : 'assistant.consent', { name: shown })}</p>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('assistant.add', { name: shown })} busyLabel=${t('assistant.adding')}
        run=${add} errorTo=${setError} disabled=${!places.length} />
    </div>`;
}

function AssistantAccess() {
  const access = useResource(PATH, { topics: [['assistant', 'changed'].join('.')] });
  const [added, setAdded] = useState(null);
  const data = optional(access);
  if (!data) return null;
  const rows = data.assistants;
  return html`
    <${Section} id="assistant-title" title=${t('assistant.title')}>
      <p class="ag-lead ag-assistant-lead">${t('assistant.lead')}</p>
      ${
        data.pending.length > 0 &&
        html`
        <h3 class="ag-assistant-pending">${t('assistant.pending_title')}</h3>
        <p class="rf-ui-help">${t('assistant.pending_help')}</p>
        <${RowList} items=${data.pending} keyOf=${(e) => e.id} label=${t('assistant.pending_title')}
          render=${(e) => html`<${Proposal} entry=${e} />`} />`
      }
      <${RowList} items=${rows} keyOf=${(r) => r.id} label=${t('assistant.title')}
        render=${(r) => html`<${Assistant} row=${r} spaces=${data.spaces} fresh=${r.id === added} />`} />
      ${
        rows.length
          ? html`<${Disclosure} summary=${t('assistant.add_another')} kind="add">
            <${Add} spaces=${data.spaces} onAdded=${setAdded} />
          <//>`
          : html`<${Add} spaces=${data.spaces} onAdded=${setAdded} />`
      }
    <//>`;
}

provide('account.sections', { order: 40, View: AssistantAccess });
