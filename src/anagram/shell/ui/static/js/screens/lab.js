// Lab (`#/lab/:id?/:tab?`): the people of the lab, the
// lab space, and the lab settings. With no id: the first lab of the member.
// With no lab: start one, or open an invite link.
//
// The one task of the members view is "invite people": the invite is the
// one offset panel of the screen. One click makes a link with the defaults
// (one person, member, 7 days); the link shows one time, with Copy.
// Live: each `lab.*` event (task `lab.watch`) reloads the lab
// resources; a new member or item row opens in place (RowList, recipe L1).
import { html, useLayoutEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { cleanText, fmtDate } from '../core/format.js';
import { absent, invalidate, mutate, optional, useDraft, useResource } from '../core/resource.js';
import { href, navigate } from '../core/router.js';
import { provided } from '../core/slots.js';
import {
  ActionButton,
  Button,
  CheckList,
  ChoiceGroup,
  CopyField,
  Disclosure,
  DownloadLink,
  Empty,
  ErrorLine,
  Facts,
  Field,
  Row,
  RowList,
  Screen,
  Section,
  Sheet,
  Slot,
  StatusLine,
  Switch,
  TaskPanel,
  TextArea,
  TextInput,
  openSheet,
} from '../components/index.js';

const MINE = '/api/labs/mine';
const LIVE = { topics: ['lab'] };
const TABS = ['members', 'space', 'settings'];
const SETTINGS_SLOT = ['lab', 'settings'].join('.');
const MODELS_SLOT = ['lab', 'models'].join('.');
const MATCHING_SLOT = ['lab', 'matching'].join('.');
const SECTIONS_SLOT = ['lab', 'sections'].join('.');
const enc = encodeURIComponent;
const labPath = (id) => `/api/labs/${enc(id)}`;

const roleName = (role) => t(`lab.role_${role}`);
const cap = (text) => text.charAt(0).toUpperCase() + text.slice(1);

// ------------------------------------------------------------ no lab

function StartLab({ first }) {
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const start = async () => {
    // Go to the lab's own route before the list shows the new lab, so the
    // page that the person acts on is the one that stays (a route change
    // makes a new view, and its state, such as a new invite link).
    const view = await mutate('POST', '/api/labs', { name: name.trim() });
    navigate(href('lab', { id: view.id }));
    await invalidate([MINE]);
    announce(t('lab.started', { lab: view.name }));
  };
  return html`
    <${Field} id="lab-name" label=${t('lab.start_name')}>
      <${TextInput} value=${name} onInput=${setName} autocomplete="off" />
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} kind=${first ? 'primary' : 'secondary'} label=${t('lab.start_action')}
        busyLabel=${t('lab.start_busy')} run=${start} errorTo=${setError} />
    </div>`;
}

function NoLab() {
  return html`
    <${TaskPanel} label=${t('lab.start_title')}>
      <h2 class="ag-panel-title">${t('lab.start_title')}</h2>
      <${StartLab} first=${true} />
    <//>
    <p class="ag-lab-or"><a href=${href('labjoin')}>${t('lab.have_invite')}</a></p>`;
}

// ------------------------------------------------------------ invite

const USES = [1, 5, 25];
const DAYS = [1, 7, 30];

function InviteOptions({ lab, uses, setUses, role, setRole, days, setDays }) {
  return html`
    <${Disclosure} kind="add" summary=${t('lab.invite_change')}>
      <${ChoiceGroup} legend=${t('lab.invite_who')} name="invite-uses" value=${String(uses)}
        options=${USES.map((n) => ({ value: String(n), label: cap(t('lab.invite_uses', { n })) }))}
        onChange=${(v) => setUses(Number(v))} />
      ${
        lab.can.invite_admin &&
        html`
        <${ChoiceGroup} legend=${t('lab.invite_role')} name="invite-role" value=${role}
          options=${['member', 'admin'].map((r) => ({ value: r, label: roleName(r), help: t(`lab.role_${r}_help`) }))}
          onChange=${setRole} />`
      }
      <${ChoiceGroup} legend=${t('lab.invite_days')} name="invite-days" value=${String(days)}
        options=${DAYS.map((n) => ({ value: String(n), label: t('lab.days', { n }) }))}
        onChange=${(v) => setDays(Number(v))} />
    <//>`;
}

function Made({ made, again }) {
  const ref = useRef(null);
  // The link enters after the person's click (rise 8 px and show, one time).
  useLayoutEffect(() => {
    if (ref.current) ref.current.classList.add('ag-m-reveal');
  }, []);
  const settle = (e) => e.currentTarget.classList.remove('ag-m-reveal');
  return html`
    <div class="ag-lab-made" ref=${ref} onAnimationEnd=${settle}>
      <${CopyField} id="invite-link" label=${t('lab.invite_link')} value=${made.url} rows=${3} />
      <p class="rf-ui-help">${t('lab.invite_who_reads')} ${t('lab.invite_until', { date: fmtDate(made.expires_at) })}</p>
      <${Button} kind="quiet" onClick=${again}>${t('lab.invite_again')}<//>
    </div>`;
}

function Invite({ lab }) {
  const [made, setMade] = useState(null);
  const [uses, setUses] = useState(1);
  const [role, setRole] = useState('member');
  const [days, setDays] = useState(7);
  const [error, setError] = useState('');
  const make = async () => {
    const out = await mutate(
      'POST',
      `${labPath(lab.id)}/invites`,
      { role, max_uses: uses, expires_days: days },
      { invalidate: [labPath(lab.id)] },
    );
    setMade(out);
    announce(t('lab.invite_ready'));
  };
  const summary = t('lab.invite_summary', {
    who: t('lab.invite_uses', { n: uses }),
    role: roleName(role).toLowerCase(),
    days: t('lab.days', { n: days }),
  });
  return html`
    <${TaskPanel} label=${t('lab.invite_title')}>
      <h2 class="ag-panel-title">${t('lab.invite_title')}</h2>
      ${
        made
          ? html`<${Made} made=${made} again=${() => {
              setMade(null);
            }} />`
          : html`
          <p class="ag-lab-summary">${summary}</p>
          <${InviteOptions} lab=${lab} uses=${uses} setUses=${setUses} role=${role} setRole=${setRole}
            days=${days} setDays=${setDays} />
          <${ErrorLine} text=${error} />
          <div class="rf-ui-actions">
            <${ActionButton} label=${t('lab.invite_action')} busyLabel=${t('lab.invite_busy')} run=${make} errorTo=${setError} />
          </div>`
      }
    <//>`;
}

// ------------------------------------------------------------ members

function MemberSheet({ lab, member, close }) {
  const name = member.person.name;
  const [role, setRole] = useState(member.role);
  const [error, setError] = useState('');
  const path = `${labPath(lab.id)}/members/${enc(member.person.id)}`;
  const done = (text) => {
    announce(text);
    close(true);
  };
  const saveRole = async () => {
    await mutate('PUT', path, { role }, { invalidate: [labPath(lab.id), MINE] });
    done(t('lab.role_saved', { name, role: roleName(role).toLowerCase() }));
  };
  const transfer = async () => {
    await mutate('PUT', path, { transfer: true }, { invalidate: [labPath(lab.id), MINE] });
    done(t('lab.transfer_done', { name }));
  };
  const remove = async () => {
    await mutate('DELETE', path, undefined, { invalidate: [labPath(lab.id), MINE] });
    done(t('lab.removed_done', { name, lab: lab.name }));
  };
  const canRole = lab.can.role && member.role !== 'pi';
  return html`
    <${Sheet} title=${name}>
      ${
        canRole &&
        html`
        <${ChoiceGroup} legend=${t('lab.role_legend')} name="member-role" value=${role}
          options=${['admin', 'member'].map((r) => ({ value: r, label: roleName(r), help: t(`lab.role_${r}_help`) }))}
          onChange=${setRole} />
        <div class="rf-ui-actions">
          <${ActionButton} label=${t('lab.role_save')} busyLabel=${t('lab.saving')} run=${saveRole} errorTo=${setError}
            disabled=${role === member.role} />
        </div>`
      }
      ${
        lab.can.transfer &&
        html`
        <${Disclosure} kind="more" summary=${t('lab.transfer_title', { name })}>
          <p>${t('lab.transfer_text', { name })}</p>
          <${ActionButton} kind="secondary" label=${t('lab.transfer_action', { name })} busyLabel=${t('lab.saving')}
            run=${transfer} errorTo=${setError} />
        <//>`
      }
      ${
        member.can_remove &&
        html`
        <div class="ag-lab-danger">
          <p>${t('lab.remove_text', { name })}</p>
          <${ActionButton} kind="danger" label=${t('lab.remove_action', { name })} busyLabel=${t('lab.removing')}
            run=${remove} errorTo=${setError} />
        </div>`
      }
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${Button} kind="quiet" onClick=${() => close(false)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

function memberMeta(m) {
  const parts = [roleName(m.role)];
  if (m.joined_at) parts.push(t('lab.since', { date: fmtDate(m.joined_at) }));
  if (m.invited_by) parts.push(t('lab.invited_by', { name: m.invited_by.you ? t('lab.by_you') : m.invited_by.name }));
  return parts.join(', ');
}

function Members({ lab }) {
  const act = (m) => {
    const can = (lab.can.role && m.role !== 'pi') || lab.can.transfer || m.can_remove;
    if (m.you || !can) return null;
    return html`
      <${Button} kind="secondary" onClick=${() => openSheet(MemberSheet, { lab, member: m })}
        aria-label=${t('lab.manage_name', { name: m.person.name })}>${t('lab.manage')}<//>`;
  };
  return html`
    <${Section} id="lab-members" title=${t('lab.members_title')} count=${t('lab.people_n', { n: lab.members.length })}>
      <${RowList} items=${lab.members} keyOf=${(m) => m.person.id} label=${t('lab.members_title')}
        render=${(m) => html`<${Row} title=${m.you ? t('lab.you_name', { name: m.person.name }) : m.person.name}
          meta=${memberMeta(m)} action=${act(m)} />`} />
    <//>`;
}

function inviteTitle(i) {
  return i.max_uses === 1
    ? t('lab.link_one', { role: roleName(i.role).toLowerCase() })
    : t('lab.link_many', { n: i.max_uses, role: roleName(i.role).toLowerCase() });
}

function inviteMeta(i) {
  const parts = [];
  if (i.max_uses > 1) parts.push(t('lab.link_used', { n: i.uses, of: i.max_uses }));
  parts.push(t('lab.link_until', { date: fmtDate(i.expires_at) }));
  if (i.by && !i.by.you) parts.push(t('lab.link_by', { name: i.by.name }));
  return parts.join(', ');
}

function Invites({ lab }) {
  const [error, setError] = useState('');
  if (!lab.invites.length) return null;
  const close = (i) => () =>
    mutate('DELETE', `${labPath(lab.id)}/invites/${enc(i.id)}`, undefined, { invalidate: [labPath(lab.id)] });
  return html`
    <${Section} id="lab-invites" title=${t('lab.links_title')}>
      <${RowList} items=${lab.invites} keyOf=${(i) => i.id} label=${t('lab.links_title')}
        render=${(i) => html`<${Row} title=${inviteTitle(i)} meta=${inviteMeta(i)}
          action=${html`<${ActionButton} kind="secondary" label=${t('lab.link_close')} busyLabel=${t('lab.link_closing')}
            run=${close(i)} errorTo=${setError} aria-label=${t('lab.link_close_name', { link: inviteTitle(i) })} />`} />`} />
      <${ErrorLine} text=${error} />
    <//>`;
}

function LeaveSheet({ lab, close }) {
  const [error, setError] = useState('');
  const leave = async () => {
    await mutate('POST', `${labPath(lab.id)}/leave`, undefined, { invalidate: [MINE] });
    announce(t('lab.left', { lab: lab.name }));
    close(true);
    navigate(href('lab'), { replace: true });
  };
  return html`
    <${Sheet} title=${t('lab.leave_title', { lab: lab.name })}>
      <p>${t('lab.leave_text')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="danger" label=${t('lab.leave_action', { lab: lab.name })} busyLabel=${t('lab.leaving')}
          run=${leave} errorTo=${setError} />
        <${Button} kind="quiet" onClick=${() => close(false)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

function MembersView({ lab, labs }) {
  const keeper = lab.role === 'pi' || lab.role === 'admin';
  return html`
    ${lab.can.invite && html`<${Invite} lab=${lab} />`}
    ${keeper && lab.key.rotation_due && html`<${StatusLine} state="pending" text=${t('lab.key_due')} />`}
    <${Members} lab=${lab} />
    <${Invites} lab=${lab} />
    <${Slot} name=${SECTIONS_SLOT} props=${{ lab }} />
    <div class="ag-lab-foot">
      ${
        lab.can.leave &&
        html`
        <${Button} kind="quiet" onClick=${() => openSheet(LeaveSheet, { lab })}>${t('lab.leave_title', { lab: lab.name })}<//>`
      }
      ${
        labs.length === 1 &&
        html`
        <${Disclosure} kind="add" summary=${t('lab.start_another')}><${StartLab} first=${false} /><//>`
      }
    </div>`;
}

// ------------------------------------------------------------ lab space

function kindName(row, kinds) {
  if (row.type) {
    const k = kinds.find((x) => x.id === row.type);
    if (k) return k.label;
  }
  return t(`lab.kind_${row.kind}`);
}

function NoteForm({ lab }) {
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [error, setError] = useState('');
  const add = async () => {
    await mutate(
      'POST',
      `${labPath(lab.id)}/space`,
      { note: { title: title.trim(), text } },
      { invalidate: [`${labPath(lab.id)}/space`] },
    );
    setTitle('');
    setText('');
    announce(t('lab.note_added'));
  };
  return html`
    <${Disclosure} kind="add" summary=${t('lab.note_title')}>
      <${Field} id="note-title" label=${t('lab.note_name')}>
        <${TextInput} value=${title} onInput=${setTitle} autocomplete="off" />
      <//>
      <${Field} id="note-text" label=${t('lab.note_text')}>
        <${TextArea} value=${text} onInput=${setText} rows="6" />
      <//>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('lab.note_action')} busyLabel=${t('lab.note_busy')} run=${add}
          errorTo=${setError} />
      </div>
    <//>`;
}

function itemMeta(row, kinds) {
  return [kindName(row, kinds), row.author.you ? t('lab.by_you') : row.author.name, fmtDate(row.published_at)]
    .filter(Boolean)
    .join(', ');
}

function SpaceList({ lab }) {
  const space = useResource(`${labPath(lab.id)}/space`, LIVE);
  const kinds = optional(useResource('/api/kinds', { topics: ['item'] })) || [];
  if (space.error.value && !space.data.value) return html`<${ErrorLine} text=${space.error.value.message} />`;
  const data = space.data.value;
  if (!data) return html`<p class="ag-empty" role="status">${t('common.loading')}</p>`;
  return html`
    <${NoteForm} lab=${lab} />
    <${RowList} items=${data.items} keyOf=${(r) => r.id} label=${t('lab.space_title')}
      render=${(r) => html`<${Row} title=${cleanText(r.title) || t('lab.untitled')} meta=${itemMeta(r, kinds)}
        note=${r.attachments ? t('lab.files_n', { n: r.attachments }) : null}
        href=${href('lab', { id: lab.id, tab: 'space' }, { item: r.id })} />`}
      empty=${html`<${Empty} text=${t('lab.space_empty')} action=${{ href: href('library'), label: t('lab.open_library') }} />`} />`;
}

function ItemView({ lab, itemId }) {
  const path = `${labPath(lab.id)}/space/${enc(itemId)}`;
  const item = useResource(path, LIVE);
  const kinds = optional(useResource('/api/kinds', { topics: ['item'] })) || [];
  const [error, setError] = useState('');
  const back = href('lab', { id: lab.id, tab: 'space' });
  if (absent(item)) {
    return html`<${Empty} text=${t('lab.item_gone')} action=${{ href: back, label: t('lab.back_space') }} />`;
  }
  if (item.error.value && !item.data.value) {
    return html`<${ErrorLine} text=${item.error.value.message} />`;
  }
  const data = item.data.value;
  if (!data) return html`<p class="ag-empty" role="status">${t('common.loading')}</p>`;
  const row = data.item;
  const remove = async () => {
    await mutate('DELETE', path, undefined, { invalidate: [`${labPath(lab.id)}/space`] });
    announce(t('lab.item_removed'));
    navigate(back, { replace: true });
  };
  const text = cleanText(data.text);
  return html`
    <p class="ag-back"><a href=${back}>${t('lab.back_space')}</a></p>
    <article class="ag-lab-item" aria-labelledby="lab-item-title">
      <h2 class="ag-section" id="lab-item-title">${cleanText(row.title) || t('lab.untitled')}</h2>
      <${Facts} rows=${[
        [t('lab.item_kind'), kindName(row, kinds)],
        [t('lab.item_by'), row.author.you ? t('lab.by_you') : row.author.name],
        [t('lab.item_added'), fmtDate(row.published_at)],
      ]} />
      ${data.finding?.claim && html`<p class="ag-quote">${data.finding.claim}</p>`}
      ${text && html`<div class="ag-lab-text">${text}</div>`}
      ${
        data.attachments.length > 0 &&
        html`
        <ul class="ag-plain ag-lab-files" aria-label=${t('lab.files_title')}>
          ${data.attachments.map(
            (a) => html`
            <li key=${a.n} class="ag-lab-file">
              <span>${a.name}</span>
              <${DownloadLink} kind="link" href=${`${path}/files/${a.n}`} filename=${a.name}
                label=${t('lab.download')} name=${t('lab.download_name', { name: a.name })} />
            </li>`,
          )}
        </ul>`
      }
      ${
        data.can_remove &&
        html`
        <div class="rf-ui-actions">
          <${ActionButton} kind="quiet" label=${t('lab.item_remove')} busyLabel=${t('lab.removing')} run=${remove}
            errorTo=${setError} />
        </div>`
      }
      <${ErrorLine} text=${error} />
    </article>`;
}

// ------------------------------------------------------------ settings

function useSave(lab) {
  const [state, setState] = useState(null);
  const save = async (changes) => {
    setState({ state: 'pending', text: t('lab.saving') });
    try {
      await mutate('PUT', `${labPath(lab.id)}/settings`, changes, { invalidate: [`${labPath(lab.id)}/settings`] });
      setState({ state: 'saved', text: t('lab.saved') });
    } catch (err) {
      setState({ state: 'error', text: err.message });
    }
  };
  return [state, save];
}

function SourcesSetting({ lab, st }) {
  const [status, save] = useSave(lab);
  const value = st.settings.sources;
  const all = st.source_kinds.map((k) => k.kind);
  const allowed = value.allowed_kinds === null ? all : value.allowed_kinds;
  const put = (more) => save({ sources: { ...value, ...more } });
  return html`
    <${Section} id="lab-set-sources" title=${t('lab.set_sources')}>
      <${ChoiceGroup} legend=${t('lab.set_default')} name="lab-default" value=${value.lab_default}
        options=${['private', 'lab'].map((v) => ({ value: v, label: t(`lab.default_${v}`), help: t(`lab.default_${v}_help`) }))}
        onChange=${(v) => put({ lab_default: v })} />
      <${CheckList} legend=${t('lab.set_kinds')} name="lab-kinds"
        items=${st.source_kinds.map((k) => ({ value: k.kind, label: k.label }))} value=${allowed}
        onChange=${(v) => put({ allowed_kinds: v.length === all.length ? null : v })} />
      <${StatusLine} ...${status || {}} />
    <//>`;
}

function MatchingSetting({ lab, st }) {
  const [status, save] = useSave(lab);
  return html`
    <${Section} id="lab-set-matching" title=${t('lab.set_matching')}>
      <${Switch} id="lab-matching" label=${t('lab.matching_on')} checked=${st.settings.matching.enabled}
        onChange=${(on) => save({ matching: { enabled: on } })} />
      <${StatusLine} ...${status || {}} />
    <//>`;
}

function setFacts(st) {
  const s = st.settings;
  const oauth = Object.keys(s.oauth_clients || {}).map((p) => t(`lab.provider_${p}`));
  const kinds =
    s.sources.allowed_kinds === null
      ? t('lab.kinds_all')
      : st.source_kinds
          .filter((k) => s.sources.allowed_kinds.includes(k.kind))
          .map((k) => k.label)
          .join(', ') || t('lab.kinds_none');
  return {
    sources: [
      [t('lab.set_default'), t(`lab.default_${s.sources.lab_default}`)],
      [t('lab.set_kinds'), kinds],
    ],
    matching: [[t('lab.set_matching'), s.matching.enabled ? t('lab.on') : t('lab.off')]],
    models: [
      [
        t('lab.models'),
        s.models.profiles?.length ? t('lab.models_n', { n: s.models.profiles.length }) : t('lab.models_local'),
      ],
    ],
    disclosure: [
      [
        t('lab.set_external'),
        s.disclosure.allow_external.length
          ? t('lab.external_n', { n: s.disclosure.allow_external.length })
          : t('lab.external_none'),
      ],
    ],
    oauth_clients: [[t('lab.set_oauth'), oauth.length ? oauth.join(', ') : t('lab.oauth_none')]],
  };
}

function NameSetting({ lab }) {
  const draft = useDraft(lab.name);
  const [error, setError] = useState('');
  const save = async () => {
    await mutate(
      'PUT',
      `${labPath(lab.id)}/name`,
      { name: draft.value.trim() },
      { invalidate: [labPath(lab.id), MINE] },
    );
    announce(t('lab.saved'));
  };
  return html`
    <${Section} id="lab-set-name" title=${t('lab.set_name')}>
      <${Field} id="lab-rename" label=${t('lab.set_name')} hideLabel=${true}>
        <${TextInput} value=${draft.value} onInput=${draft.set} autocomplete="off" />
      <//>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="secondary" label=${t('lab.rename')} busyLabel=${t('lab.saving')} run=${save}
          errorTo=${setError} disabled=${!draft.dirty} />
      </div>
    <//>`;
}

const EDITORS = { sources: SourcesSetting, matching: MatchingSetting };
const ORDER = ['sources', 'matching', 'models', 'disclosure', 'oauth_clients'];

// The parts of the settings that other tracks show:
// - slot `lab.settings` (R3 S15, slots/lab_sources.js): the sections
//   `sources` and `oauth_clients`. When it has a view, R2 does not show its
//   own view or summary of those two sections.
// - slot `lab.models` (R4 11b): the sections `models` and `disclosure`.
// - slot `lab.matching`: the section `matching`, the same way.
// Each view writes only its own sections (`PUT` with one section), so the
// views do not overwrite each other.
function covered() {
  const out = new Set();
  if (provided(SETTINGS_SLOT).length) for (const n of ['sources', 'oauth_clients']) out.add(n);
  if (provided(MODELS_SLOT).length) for (const n of ['models', 'disclosure']) out.add(n);
  if (provided(MATCHING_SLOT).length) out.add('matching');
  return out;
}

function SettingsView({ lab }) {
  const res = useResource(`${labPath(lab.id)}/settings`, LIVE);
  if (res.error.value && !res.data.value) return html`<${ErrorLine} text=${res.error.value.message} />`;
  const st = res.data.value;
  if (!st) return html`<p class="ag-empty" role="status">${t('common.loading')}</p>`;
  const facts = setFacts(st);
  const others = covered();
  const plain = [];
  const views = [];
  for (const name of ORDER) {
    if (others.has(name)) continue;
    if (st.can_edit && EDITORS[name]) {
      const View = EDITORS[name];
      views.push(html`<${View} key=${name} lab=${lab} st=${st} />`);
    } else plain.push(...facts[name]);
  }
  return html`
    ${!st.can_edit && html`<p class="ag-lead">${t('lab.settings_read', { names: st.editors.join(', ') })}</p>`}
    ${st.can_edit && html`<${NameSetting} lab=${lab} />`}
    <${Slot} name=${SETTINGS_SLOT} props=${{ lab }} />
    ${views}
    <${Slot} name=${MATCHING_SLOT} props=${{ lab }} />
    <${Slot} name=${MODELS_SLOT} props=${{ lab }} />
    ${
      plain.length > 0 &&
      html`
      <${Section} id="lab-set-other" title=${st.can_edit ? t('lab.set_other') : t('lab.set_all')}>
        <${Facts} rows=${plain} />
      <//>`
    }
    ${
      st.updated_by &&
      html`
      <p class="rf-ui-help ag-lab-updated">${t('lab.updated', { name: st.updated_by.you ? t('lab.by_you') : st.updated_by.name, date: fmtDate(st.updated_at) })}</p>`
    }`;
}

// ------------------------------------------------------------ screen

function Tabs({ lab, current }) {
  return html`
    <nav class="ag-tabs" aria-label=${t('lab.views')}>
      <ul>
        ${TABS.map(
          (tab) => html`
          <li key=${tab}>
            <a href=${href('lab', { id: lab.id, tab: tab === TABS[0] ? undefined : tab })}
              aria-current=${current === tab ? 'page' : undefined}>${t(tab === 'settings' ? 'lab.settings' : `lab.tab_${tab}`)}</a>
          </li>`,
        )}
      </ul>
    </nav>`;
}

// Two labs can have the same name. A name that is not unique among the
// labs of the person gets the role, so that each link names one lab.
function labLabel(lab, labs) {
  const same = labs.filter((l) => l.name.trim().toLowerCase() === lab.name.trim().toLowerCase());
  if (same.length < 2) return lab.name;
  return t('lab.other_lab_role', { lab: lab.name, role: t(`lab.role_${lab.role}`) });
}

function OtherLabs({ labs, id }) {
  const others = labs.filter((l) => l.id !== id);
  if (!others.length) return null;
  return html`
    <p class="ag-lab-others">
      <span>${t('lab.other_labs')}</span>
      ${others.map((l, i) => html`${i ? ', ' : ' '}<a key=${l.id} href=${href('lab', { id: l.id })}>${labLabel(l, labs)}</a>`)}
    </p>`;
}

function LabView({ id, tab, query, labs }) {
  const lab = useResource(labPath(id), LIVE);
  const gone = lab.error.value && lab.error.value.status === 404;
  if (gone) {
    return html`
      <${Screen} title=${t('lab.title')}>
        <${Empty} text=${t('lab.not_in')} action=${{ href: href('lab'), label: t('lab.your_labs') }} />
      <//>`;
  }
  const data = lab.data.value;
  return html`
    <${Screen} title=${data ? data.name : t('lab.title')} resources=${[lab]}>
      ${() => html`
        <${OtherLabs} labs=${labs} id=${id} />
        <${Tabs} lab=${data} current=${tab} />
        ${tab === 'members' && html`<${MembersView} lab=${data} labs=${labs} />`}
        ${
          tab === 'space' &&
          (query.item ? html`<${ItemView} lab=${data} itemId=${query.item} />` : html`<${SpaceList} lab=${data} />`)
        }
        ${tab === 'settings' && html`<${SettingsView} lab=${data} />`}`}
    <//>`;
}

function View({ params, query }) {
  const mine = useResource(MINE, LIVE);
  const labs = mine.data.value;
  // A lab that the route names but the list does not show yet (just
  // started; the list reloads): wait, so the start form does not come back.
  const waiting = labs && params.id && !labs.some((l) => l.id === params.id) && mine.state.value !== 'ready';
  if (!labs || waiting) return html`<${Screen} title=${t('lab.title')} resources=${[mine]}>${() => null}<//>`;
  if (!labs.length) {
    return html`<${Screen} title=${t('lab.title')} resources=${[mine]}>${() => html`<${NoLab} />`}<//>`;
  }
  const id = params.id || labs[0].id;
  const tab = TABS.includes(params.tab) ? params.tab : TABS[0];
  return html`<${LabView} key=${id} id=${id} tab=${tab} query=${query || {}} labs=${labs} />`;
}

export const screen = { id: 'lab', path: '/lab/:id?/:tab?', nav: { group: 'main', order: 50 }, View };
