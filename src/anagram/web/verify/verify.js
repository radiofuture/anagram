// The verify page (R5 step 13). A person drops a proof certificate or a
// proof file, and optionally the files of the finding. The node checks the
// proof against its own log (POST /verify). This browser computes the
// content digest of each other file and compares it with the opened
// digests; a file never leaves the browser. Content goes into the page as
// text only.
import { contentDigest } from './anagram-crypto.js';

const WORDS = {
  checking: 'Checking the proof…',
  hashing: 'Comparing {name}…',
  no_proof: 'None of these files is a proof. Add a certificate (.html) or a proof file (.json).',
  bad_proof: 'This file is not a proof that this page can read.',
  failed: 'The check did not finish. Try again.',
  too_many: 'Too many checks from this address. Wait one minute and try again.',
  no_crypto: 'This browser cannot compare files on this page. Use the Anagram command.',
  not_found: 'No proof is published at this address.',
  other_node: 'This proof is from another node: {origin}. Check it on that node, or with the Anagram command.',
  valid: 'Valid proof',
  invalid: 'Not a valid proof',
  invalid_text: 'This proof did not pass all checks. Do not trust it.',
  statement: 'This record existed no later than ',
  no_time: 'The time of this record is not proven.',
  fake: 'A test anchor is in this proof. It proves no time.',
  record: 'The record',
  root: 'Finding fingerprint',
  finding: 'Finding ID',
  version: 'Version',
  key: 'Signing key',
  witness: 'Witness signature',
  anchors: 'Independent time',
  anchor_none: 'None',
  pending: 'Pending',
  not_counted: 'Not counted',
  test_anchor: 'Test anchor',
  log: 'Public log',
  entry: 'Entry {i}, in a log of {n}',
  files: 'Files',
  files_none: 'The proof does not show the files.',
  file_n: 'File {n}',
  same: 'Same file',
  other: 'Not a file of this record',
  not_added: 'Not added',
  failed_checks: 'Checks that failed',
  limits: 'What this does not prove',
  limit_1: 'That the owner made the work. It shows only that the key signed the record, and when the log had it.',
  limit_2: 'What the files mean.',
  limit_3: 'Anything about the parts of the record that the proof does not show.',
};

let shown = null; // the bundle of a published proof (GET /verify/<root>)

const $ = (id) => document.getElementById(id);
const say = (key, params = {}) => WORDS[key].replace(/\{(\w+)\}/g, (all, k) => (k in params ? String(params[k]) : all));

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null) continue;
    if (k === 'class') node.className = v;
    else node.setAttribute(k, String(v));
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

function state(text, kind = 'info') {
  const s = $('state');
  s.textContent = text || '';
  s.dataset.kind = kind;
}

const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];
const pad = (n) => String(n).padStart(2, '0');

/** "16 November 2026, 19:49:38 UTC". Seconds stay: a rounded time would claim more. */
function when(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return (
    `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}, ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
  );
}

const groups = (hex, n = 4) => (hex || '').match(new RegExp(`.{1,${n}}`, 'g'))?.join(' ') || '';

function anchorState(text) {
  if (text.startsWith('valid, ')) return when(text.slice(7));
  if (text.startsWith('pending')) return WORDS.pending;
  return WORDS.not_counted;
}

function fact(label, ...value) {
  return el('div', {}, el('dt', {}, label), el('dd', {}, ...value));
}

function isProof(text) {
  return text.includes('id="anagram-proof"') || /"schema"\s*:\s*"anagram\.proof_bundle/.test(text);
}

async function post(body) {
  let res;
  try {
    res = await fetch('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error(WORDS.failed);
  }
  if (res.status === 429) throw new Error(WORDS.too_many);
  if (res.status === 400 || res.status === 413) throw new Error(WORDS.bad_proof);
  if (!res.ok) throw new Error(WORDS.failed);
  return res.json();
}

/** For each added file: the slot it equals, or null. */
async function compare(files, evidence) {
  const out = [];
  for (const file of files) {
    let slot = null;
    for (const [s, fields] of Object.entries(evidence)) {
      const c = fields.content;
      if (!c || c.size !== file.size) continue;
      state(say('hashing', { name: file.name }));
      const got = await contentDigest(file, c.chunk_size);
      if (got.digest === c.digest) {
        slot = s;
        break;
      }
    }
    out.push({ file, slot });
  }
  return out;
}

function render(report, matches) {
  const box = $('result');
  box.replaceChildren();
  const ok = Boolean(report.ok);
  box.append(el('p', { class: 'vf-verdict', 'data-ok': String(ok) }, ok ? WORDS.valid : WORDS.invalid));
  box.append(el('h2', { class: 'vf-title', id: 'result-title' }, report.title));
  if (!ok) box.append(el('p', { class: 'vf-statement' }, WORDS.invalid_text));
  else if (report.not_after) {
    box.append(el('p', { class: 'vf-statement' }, WORDS.statement, el('strong', {}, when(report.not_after)), '.'));
  } else box.append(el('p', { class: 'vf-statement' }, WORDS.no_time));
  if (report.fake) box.append(el('p', { class: 'vf-warn', role: 'note' }, WORDS.fake));

  // Files: the opened items, and each added file that equals one of them.
  const evidence = Object.entries(report.evidence || {});
  box.append(el('h3', { class: 'vf-h' }, WORDS.files));
  if (!evidence.length) box.append(el('p', {}, WORDS.files_none));
  else {
    const bySlot = new Map(matches.filter((m) => m.slot !== null).map((m) => [m.slot, m.file]));
    const items = evidence.map(([slot, f]) => {
      const name = f.name || say('file_n', { n: Number(slot) + 1 });
      const added = bySlot.get(slot);
      const match = added
        ? el('span', { class: 'vf-match', 'data-state': 'same' }, WORDS.same)
        : el('span', { class: 'vf-match' }, WORDS.not_added);
      return el(
        'li',
        { 'data-slot': slot },
        el('span', { class: 'vf-name' }, name),
        match,
        f.content ? el('span', { class: 'vf-digest vf-mono' }, groups(f.content.digest, 8)) : null,
      );
    });
    const strays = matches
      .filter((m) => m.slot === null)
      .map((m) =>
        el(
          'li',
          {},
          el('span', { class: 'vf-name' }, m.file.name),
          el('span', { class: 'vf-match', 'data-state': 'other' }, WORDS.other),
        ),
      );
    box.append(el('ul', { class: 'vf-files' }, items, strays));
  }

  box.append(el('h3', { class: 'vf-h' }, WORDS.record));
  const rec = [fact(WORDS.root, el('span', { class: 'vf-mono' }, groups(report.root)))];
  if (report.opened?.finding_id)
    rec.push(fact(WORDS.finding, el('span', { class: 'vf-mono' }, groups(report.opened.finding_id))));
  if (report.opened?.version) rec.push(fact(WORDS.version, report.opened.version));
  rec.push(fact(WORDS.key, el('span', { class: 'vf-mono' }, groups(report.owner_key))));
  rec.push(fact(WORDS.witness, report.witness_time ? when(report.witness_time) : WORDS.anchor_none));
  const anchors = (report.anchors || []).map(([label, s]) =>
    el('div', {}, label.startsWith('fake') ? WORDS.test_anchor : label, ': ', anchorState(s)),
  );
  rec.push(fact(WORDS.anchors, anchors.length ? anchors : WORDS.anchor_none));
  rec.push(fact(WORDS.log, report.log.origin, el('br'), say('entry', { i: report.log.index, n: report.log.size })));
  box.append(el('dl', { class: 'vf-facts' }, rec));

  const failed = (report.checks || []).filter((c) => !c.ok);
  if (failed.length) {
    box.append(el('h3', { class: 'vf-h' }, WORDS.failed_checks));
    box.append(
      el(
        'ul',
        { class: 'vf-limits' },
        failed.map((c) => el('li', {}, c.detail ? `${c.name}: ${c.detail}` : c.name)),
      ),
    );
  }
  box.append(el('h3', { class: 'vf-h' }, WORDS.limits));
  box.append(
    el(
      'ul',
      { class: 'vf-limits' },
      [WORDS.limit_1, WORDS.limit_2, WORDS.limit_3].map((t) => el('li', {}, t)),
    ),
  );
  box.hidden = false;
}

async function run(body, others) {
  $('result').hidden = true;
  state(WORDS.checking);
  const report = await post(body);
  if (report.other_node) {
    state(say('other_node', { origin: report.other_node }), 'error');
    return;
  }
  let matches = [];
  if (others.length) {
    if (!globalThis.crypto?.subtle) state(WORDS.no_crypto, 'error');
    else matches = await compare(others, report.evidence || {});
  }
  render(report, matches);
  state('');
}

async function take(fileList) {
  const files = [...fileList];
  let proof = null;
  const others = [];
  for (const f of files) {
    if (!proof && f.size < 4 << 20 && /\.(html?|json)$/i.test(f.name)) {
      const text = await f.text();
      if (isProof(text)) {
        proof = text;
        continue;
      }
    }
    others.push(f);
  }
  if (!proof && !shown) {
    state(WORDS.no_proof, 'error');
    return;
  }
  try {
    await run(proof ? { text: proof } : { bundle: shown }, others);
  } catch (err) {
    state(err.message, 'error');
  }
}

async function published(root) {
  let res;
  try {
    res = await fetch(`/proofs/${root}`, { headers: { Accept: 'application/json' } });
  } catch {
    state(WORDS.failed, 'error');
    return;
  }
  if (!res.ok) {
    state(res.status === 404 ? WORDS.not_found : WORDS.failed, 'error');
    return;
  }
  const { bundle } = await res.json();
  shown = bundle;
  try {
    await run({ bundle }, []);
  } catch (err) {
    state(err.message, 'error');
  }
}

function start() {
  const input = $('files');
  const drop = $('drop');
  input.addEventListener('change', () => {
    if (input.files.length) take(input.files);
  });
  // A drop on the input works by default; the mark shows where the drop goes.
  drop.addEventListener('dragenter', () => {
    drop.dataset.over = 'true';
  });
  drop.addEventListener('dragleave', () => {
    drop.dataset.over = 'false';
  });
  drop.addEventListener('drop', () => {
    drop.dataset.over = 'false';
  });
  const m = /^\/verify\/([0-9a-f]{64})$/.exec(location.pathname);
  if (m) published(m[1]);
}

start();
