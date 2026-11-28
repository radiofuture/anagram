// Finding screen: the outputs of a proven finding.
//
// finding.actions:  "Save certificate" (the primary output for a reader: one
//                   HTML file to print, save as PDF, or send; it holds the
//                   proof) and "Make a preprint draft" (opens a sheet with
//                   the authors and the abstract).
//                   "Save certificate" opens one sheet: what the
//                   certificate shows, the save, and the public link (W15).
import { html, signal, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { provide } from '../core/slots.js';
import { mutate, optional, useResource } from '../core/resource.js';
import {
  ActionButton,
  Button,
  Check,
  CheckList,
  CopyField,
  ErrorLine,
  Field,
  Sheet,
  TextArea,
  openSheet,
} from '../components/index.js';

const PARTS = ['claim', 'files', 'digests', 'name'];

// The parts that the certificate shows, for one finding. The sheet keeps
// the last choice while the page is open.
const chosen = signal({ root: null, parts: PARTS });

function partsOf(root) {
  return chosen.value.root === root ? chosen.value.parts : PARTS;
}

const isProven = (finding) => Boolean(finding.versions[0]?.proven_by);

/** The file name of a Content-Disposition header, or the fallback. */
function fileName(res, fallback) {
  const m = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '');
  return m ? m[1] : fallback;
}

/**
 * Get a file from a route and give it to the browser as a download. An
 * error of the route comes back as its plain message.
 */
export async function saveFrom(method, path, body, fallback) {
  const init = { method, credentials: 'same-origin', headers: { Accept: '*/*' } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new Error(t('common.no_answer'));
  }
  if (!res.ok) {
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    throw new Error(data?.error || t('common.failed'));
  }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName(res, fallback);
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  return a.download;
}

const linkPath = (root) => `/api/findings/${root}/public-proof`;

/**
 * The public link of the proof on the verify page of the node.
 * Not offered when the node has no public proof page (`available` false).
 */
function PublicLink({ root, link, parts, setError }) {
  const path = linkPath(root);
  const data = optional(link);
  if (!data?.available) return null;
  const url = data.url || null;
  const publish = async () => {
    const body = Object.fromEntries(PARTS.filter((p) => p !== 'name').map((p) => [p, parts.includes(p)]));
    await mutate('POST', path, body, { invalidate: [path] });
    announce(t('certify.link_made'));
  };
  const remove = async () => {
    await mutate('DELETE', path, undefined, { invalidate: [path] });
    announce(t('certify.link_removed'));
  };
  if (!url) {
    return html`
      <${ActionButton} kind="secondary" label=${t('certify.link_make')} busyLabel=${t('certify.link_busy')}
        run=${publish} errorTo=${setError} />`;
  }
  return html`
    <div class="ag-certify-link">
      <${CopyField} id="public-proof" label=${t('certify.link_label')} value=${url} rows=${1} />
      <${ActionButton} kind="quiet" label=${t('certify.link_stop')} busyLabel=${t('certify.link_stop_busy')}
        run=${remove} errorTo=${setError} />
    </div>`;
}

/**
 * The certificate sheet (W15): what the certificate shows, the save, and the
 * public link of the proof. One place for each output of the proof.
 */
function CertificateSheet({ finding, close }) {
  const [error, setError] = useState('');
  const [parts, setParts] = useState(partsOf(finding.root));
  const root = encodeURIComponent(finding.root);
  const link = useResource(linkPath(root));
  const linkable = Boolean(optional(link)?.available);
  const choose = (next) => {
    setParts(next);
    chosen.value = { root: finding.root, parts: next };
  };
  const save = async () => {
    const query = PARTS.map((p) => `${p}=${parts.includes(p) ? 1 : 0}`).join('&');
    await saveFrom('GET', `/api/findings/${root}/certificate?${query}`, undefined, 'certificate.html');
    announce(t('certify.saved'));
    close(true);
  };
  return html`
    <${Sheet} title=${t('certify.title')}>
      <p class="rf-ui-help">${t('certify.help')}</p>
      <${CheckList} legend=${t('certify.show')} name="certificate-part" value=${parts} onChange=${choose}
        items=${PARTS.map((p) => ({ value: p, label: t(`certify.part_${p}`) }))} />
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('certify.save')} busyLabel=${t('certify.save_busy')} run=${save} errorTo=${setError} />
        <${Button} kind="quiet" onClick=${() => close(null)}>${t('common.cancel')}<//>
      </div>
      ${
        linkable &&
        html`
        <h3 class="ag-subtitle">${t('certify.link_title')}</h3>
        <p class="rf-ui-help">${t('certify.link_help')}</p>
        <div class="rf-ui-actions">
          <${PublicLink} root=${root} link=${link} parts=${parts} setError=${setError} />
        </div>`
      }
    <//>`;
}

/** The primary action of the proof panel: it opens the certificate sheet. */
function SaveCertificate({ finding }) {
  if (!isProven(finding)) return null;
  return html`<${Button} onClick=${() => openSheet(CertificateSheet, { finding })}>${t('certify.save')}<//>`;
}

// One author on each line: the name, then the ORCID iD if there is one.
const ORCID = /^(?:[a-z]+-)?\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/i;

export function parseAuthors(text) {
  return String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split(',').map((p) => p.trim());
      const last = parts.length > 1 ? parts[parts.length - 1] : '';
      if (ORCID.test(last)) return { name: parts.slice(0, -1).join(', '), orcid: last };
      return { name: line, orcid: null };
    });
}

function ownerLine(ov) {
  if (!ov?.name) return '';
  return ov.orcid ? `${ov.name}, ${ov.orcid}` : ov.name;
}

/**
 * The preprint draft: a zip with the manuscript and the proofs.
 * The authors start as the owner; the person can add co-authors and an
 * abstract before the save.
 */
function PreprintSheet({ finding, close }) {
  const overview = useResource('/api/overview');
  const [files, setFiles] = useState(true);
  const [authors, setAuthors] = useState(null); // null: not changed, use the owner line
  const [abstract, setAbstract] = useState('');
  const [error, setError] = useState('');
  const root = encodeURIComponent(finding.root);
  const shown = authors === null ? ownerLine(optional(overview)) : authors;
  const save = async () => {
    const list = parseAuthors(shown);
    if (!list.length) throw new Error(t('certify.draft_authors_need'));
    const body = { include_files: files, authors: list };
    if (abstract.trim()) body.abstract = abstract.trim();
    await saveFrom('POST', `/api/findings/${root}/preprint`, body, 'preprint.zip');
    announce(t('certify.draft_saved'));
    close(true);
  };
  return html`
    <${Sheet} title=${t('certify.draft_title')}>
      <p class="rf-ui-help">${t('certify.draft_help')}</p>
      <${Field} id="preprint-authors" label=${t('certify.draft_authors')} help=${t('certify.draft_authors_help')}>
        <${TextArea} value=${shown} onInput=${setAuthors} rows="3" spellcheck=${false} />
      <//>
      <${Field} id="preprint-abstract" label=${t('certify.draft_abstract')}>
        <${TextArea} value=${abstract} onInput=${setAbstract} rows="5" />
      <//>
      <${Check} id="preprint-files" label=${t('certify.draft_files')} checked=${files} onChange=${setFiles} />
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('certify.draft_save')} busyLabel=${t('certify.draft_busy')}
          run=${save} errorTo=${setError} />
        <${Button} kind="quiet" onClick=${() => close(null)}>${t('common.cancel')}<//>
      </div>
    <//>`;
}

function PreprintAction({ finding }) {
  if (!isProven(finding)) return null;
  return html`
    <${Button} kind="secondary" onClick=${() => openSheet(PreprintSheet, { finding })}>${t('certify.draft_open')}<//>`;
}

provide('finding.actions', { order: 5, View: SaveCertificate });
provide('finding.actions', { order: 20, View: PreprintAction });
