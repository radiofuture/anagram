// Sharing on the finding screen.
//
// finding.actions:  "Share" opens the share sheet: one field for a name, an
//                   email address, or an ORCID iD; the rings come below it.
// finding.sections: "Shared with": one row for each person, lab, or invite,
//                   with its state. A read changes the row in place (S1).
//                   "Stop sharing" opens the stop sheet.
import { html, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { api, search } from '../core/api.js';
import { fmtDate } from '../core/format.js';
import { provide } from '../core/slots.js';
import { invalidate, optional, useResource } from '../core/resource.js';
import { href, navigate } from '../core/router.js';
import {
  ActionButton,
  Button,
  ChipList,
  CopyField,
  Empty,
  ErrorLine,
  Row,
  RowList,
  SearchSelect,
  Section,
  Sheet,
  openSheet,
} from '../components/index.js';
import { StateLine, personName } from '../parts/shares.js';

const PUBLIC = 'Everyone';

function paths(finding) {
  const base = `/api/findings/${encodeURIComponent(finding.root)}`;
  return { base, shares: `${base}/shares` };
}

function reload(finding) {
  return invalidate([paths(finding).shares, paths(finding).base, '/api/findings', '/api/history', '/api/rings']);
}

// ------------------------------------------------------------- share sheet

/** The words of the other people in the files, and the choice to go on. */
function ThirdParty({ items, yes, busy, onYes, onBack }) {
  const [error, setError] = useState('');
  return html`
    <p>${t('sharing.third_text')}</p>
    <ul>${items.map((i) => html`<li key=${i}>${i}</li>`)}</ul>
    <p>${t('sharing.third_ask')}</p>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${yes} busyLabel=${busy} run=${onYes} errorTo=${setError} />
      <${Button} kind="secondary" onClick=${onBack}>${t('sharing.back')}<//>
    </div>`;
}

/** Invite links that the owner sends: an ORCID iD has no address for the node. */
function Links({ links, close }) {
  return html`
    <p>${t('sharing.links_text')}</p>
    ${links.map(
      (l, i) => html`
      <${CopyField} key=${l.invite_id} id=${`invite-link-${i}`} label=${t('sharing.link_label', { name: l.label })}
        value=${l.link} rows=${2} />`,
    )}
    <div class="rf-ui-actions">
      <${Button} onClick=${() => close(true)}>${t('sharing.done')}<//>
    </div>`;
}

function shareLabel(chosen) {
  if (chosen.length === 1) return t('sharing.share_action', { name: chosen[0].label });
  return t('sharing.share_action_n', { n: chosen.length });
}

function ShareSheet({ finding, rings, close }) {
  const [chosen, setChosen] = useState([]);
  const [field, setField] = useState(0); // a new key empties the search field
  const [step, setStep] = useState('pick'); // pick | third | links
  const [third, setThird] = useState([]);
  const [links, setLinks] = useState([]);
  const [error, setError] = useState('');
  const found = useRef(new Map()); // short key -> target (the widget limits ids to 80 characters)
  const { base, shares } = paths(finding);

  const has = (id) => chosen.some((c) => c.id === id);
  const lookup = async (q, signal) => {
    const people = await search(`/api/share/targets?q=${encodeURIComponent(q)}`, signal);
    const low = q.trim().toLowerCase();
    const ringHits = rings
      .filter((r) => r.name.toLowerCase().includes(low))
      .map((r) => ({
        id: `ring:${r.name}`,
        kind: 'ring',
        ring: r.name,
        label: r.name,
        detail: t('sharing.ring_detail'),
      }));
    const all = [...people, ...ringHits].filter((p) => !has(p.id));
    found.current = new Map(all.map((p, i) => [`t${i}`, p]));
    return all.map((p, i) => ({ id: `t${i}`, label: p.label, detail: p.detail }));
  };
  const add = (target) => {
    if (!target || has(target.id)) return;
    setChosen((old) => [...old, target]);
    setError('');
  };
  const pick = (state) => {
    if (!state.selected) return;
    add(found.current.get(state.selected.id));
    setField((n) => n + 1);
    // The new field gets the focus, so that the next name can follow.
    requestAnimationFrame(() => {
      const input = document.querySelector('.ag-share-field input');
      if (input) input.focus();
    });
  };
  const remove = (item) => setChosen((old) => old.filter((c) => c.id !== item.id));

  const send = async (ack) => {
    const people = chosen.filter((c) => c.kind !== 'ring').map((c) => c.id);
    const out = { invited: [] };
    if (people.length) {
      const got = await api('POST', shares, { targets: people, ack_third_party: ack });
      out.invited = got.invited || [];
    }
    for (const c of chosen.filter((x) => x.kind === 'ring')) {
      await api('POST', `${base}/share`, { ring: c.ring, ack_third_party: ack });
    }
    await reload(finding);
    const unsent = out.invited.filter((i) => !i.mailed && i.link);
    if (unsent.length) {
      setLinks(unsent);
      setStep('links');
      return;
    }
    close(true);
  };
  const share = async () => {
    if (!chosen.length) throw new Error(t('sharing.share_need'));
    try {
      await send(false);
    } catch (err) {
      if (err.status !== 409 || !err.data.third_party) throw err;
      setThird(err.data.third_party);
      setStep('third');
    }
  };

  if (step === 'third') {
    return html`
      <${Sheet} title=${t('sharing.third_title')}>
        <${ThirdParty} items=${third} yes=${t('sharing.third_yes')} busy=${t('sharing.share_busy')}
          onYes=${() => send(true)} onBack=${() => setStep('pick')} />
      <//>`;
  }
  if (step === 'links') {
    return html`<${Sheet} title=${t('sharing.links_title')}><${Links} links=${links} close=${close} /><//>`;
  }
  const people = chosen.filter((c) => c.kind !== 'ring' && c.kind !== 'lab');
  const invites = chosen.some((c) => c.kind === 'invite_email' || c.kind === 'invite_orcid');
  const open = rings.filter((r) => !has(`ring:${r.name}`));
  return html`
    <${Sheet} title=${t('sharing.share_title')}>
      <div class="ag-share-field">
        <${SearchSelect} key=${field} id=${`share-with-${field}`} label=${t('sharing.share_field')}
          placeholder=${t('sharing.share_placeholder')} search=${lookup} onChange=${pick} />
      </div>
      <${ChipList} items=${chosen} label=${t('sharing.chosen')} onRemove=${remove}
        removeLabel=${(c) => t('sharing.remove_chosen', { name: c.label })} />
      ${
        open.length > 0 &&
        html`
        <div class="ag-share-rings">
          <p class="rf-ui-help" id="share-rings">${t('sharing.share_rings')}</p>
          <ul class="ag-plain" aria-labelledby="share-rings">
            ${open.map(
              (r) => html`
              <li key=${r.name}>
                <button type="button" class="ag-link"
                  onClick=${() => add({ id: `ring:${r.name}`, kind: 'ring', ring: r.name, label: r.name })}>${r.name}</button>
              </li>`,
            )}
          </ul>
        </div>`
      }
      ${people.length > 0 && html`<p class="rf-ui-help">${t('sharing.share_record')}</p>`}
      ${invites && html`<p class="rf-ui-help">${t('sharing.share_invite')}</p>`}
      ${has('ring:Public') && html`<p class="rf-ui-help">${t('sharing.ring_public')}</p>`}
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${chosen.length ? shareLabel(chosen) : t('sharing.share')} busyLabel=${t('sharing.share_busy')}
          run=${share} errorTo=${setError} />
        <${Button} kind="secondary" onClick=${() => close(null)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

function ShareAction({ finding }) {
  const rings = useResource('/api/rings', { topics: ['ring.changed'] });
  const open = async () => {
    await rings.load();
    openSheet(ShareSheet, { finding, rings: optional(rings) || [] });
  };
  return html`<${Button} kind="secondary" onClick=${open}>${t('sharing.share')}<//>`;
}

// -------------------------------------------------------------- stop sheet

function stopWords(row) {
  const name = personName(row);
  if (row.person.kind === 'lab') {
    return {
      title: t('sharing.stop_lab_title'),
      text: [t('sharing.stop_lab_text')],
      action: t('sharing.stop_lab_action'),
    };
  }
  if (row.person.kind === 'invite') {
    return {
      title: t('sharing.stop_invite_title', { name }),
      text: [t('sharing.stop_invite_text', { name })],
      action: t('sharing.stop_invite_action'),
    };
  }
  const read = row.reads
    ? t('sharing.stop_reads', { name, n: row.reads, date: fmtDate(row.last_read_at) })
    : t('sharing.stop_unread', { name });
  return {
    title: t('sharing.stop_title', { name }),
    text: [t('sharing.stop_text', { name }), t('sharing.stop_kept', { name }), read],
    action: t('sharing.stop_action'),
  };
}

function StopSheet({ finding, row, keep, close }) {
  const [stopped, setStopped] = useState(false);
  const [error, setError] = useState('');
  const { base } = paths(finding);
  const words = stopWords(row);
  const stop = async () => {
    await api('POST', `${base}/shares/stop`, { target: row.target });
    await reload(finding);
    // A new key is a second, explicit action. It needs the files.
    if (row.person.kind === 'member' && finding.evidence.every((e) => e.on_this_computer)) setStopped(true);
    else close(true);
  };
  const [third, setThird] = useState(null);
  const rekey = async (ack) => {
    let out;
    try {
      out = await api('POST', `${base}/rekey`, { ack_third_party: ack });
    } catch (err) {
      if (err.status !== 409 || !err.data.third_party) throw err;
      setThird(err.data.third_party);
      return;
    }
    await invalidate(['/api/findings', '/api/history']);
    close(true);
    navigate(href('finding', { root: out.finding.root }));
  };
  if (third) {
    return html`
      <${Sheet} title=${t('sharing.third_title')}>
        <${ThirdParty} items=${third} yes=${t('sharing.rekey_yes')} busy=${t('sharing.rekey_busy')}
          onYes=${() => rekey(true)} onBack=${() => setThird(null)} />
      <//>`;
  }
  if (stopped) {
    return html`
      <${Sheet} title=${t('sharing.stopped_title', { name: personName(row) })}>
        <p>${keep ? t('sharing.rekey_text', { n: keep }) : t('sharing.rekey_none')}</p>
        <${ErrorLine} text=${error} />
        <div class="rf-ui-actions">
          <${ActionButton} kind="secondary" label=${t('sharing.rekey_action')} busyLabel=${t('sharing.rekey_busy')}
            run=${() => rekey(false)} errorTo=${setError} />
          <${Button} onClick=${() => close(true)}>${t('sharing.done')}<//>
        </div>
      <//>`;
  }
  return html`
    <${Sheet} title=${words.title}>
      ${words.text.map((line) => html`<p key=${line}>${line}</p>`)}
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} kind="danger" label=${words.action} busyLabel=${t('sharing.stop_busy')} run=${stop} errorTo=${setError} />
        <${Button} kind="secondary" onClick=${() => close(null)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

// ---------------------------------------------------------- "Shared with"

function SharedWithRow({ finding, row, keep }) {
  const name = personName(row);
  const stop = () => openSheet(StopSheet, { finding, row, keep: row.state === 'stopped' ? keep : keep - 1 });
  const action =
    row.state === 'stopped'
      ? null
      : html`
    <button type="button" class="ag-link" aria-label=${t('sharing.stop_name', { name })} onClick=${stop}>
      ${t('sharing.stop')}
    </button>`;
  const to = row.person.subject ? href('history', { subject: row.person.subject }) : undefined;
  return html`<${Row} title=${name} href=${to} meta=${html`<${StateLine} row=${row} />`} action=${action} />`;
}

function SharedWith({ finding }) {
  const { shares } = paths(finding);
  const audience = useResource(shares, { topics: ['share', 'finding.changed'] });
  const data = optional(audience);
  const rows = data ? data.audience : null;
  const isPublic = finding.versions[0].shared_with.includes(PUBLIC);
  const keep = rows ? rows.filter((r) => r.person.kind === 'member' && r.state !== 'stopped').length : 0;
  return html`
    <${Section} id="shared-with-title" title=${t('sharing.with_title')}>
      ${isPublic && html`<p class="ag-share-public">${t('sharing.public')}</p>`}
      <${RowList} items=${rows} keyOf=${(r) => r.target} label=${t('sharing.with_title')}
        render=${(r) => html`<${SharedWithRow} finding=${finding} row=${r} keep=${keep} />`}
        empty=${isPublic ? null : html`<${Empty} text=${t('sharing.with_empty')} />`} />
    <//>`;
}

provide('finding.actions', { order: 10, View: ShareAction });
provide('finding.sections', { order: 10, View: SharedWith });
