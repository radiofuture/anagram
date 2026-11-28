// The "Labs" section of the organizer page (`/admin`). It reads
// `GET /admin/api/labs` and replaces the plain list in `#ag-admin-labs`.
// For each lab: counts and sizes (never content), the space limit, and
// read-only on or off. A change sends the CSRF value of the session.
(() => {
  const mount = document.getElementById('ag-admin-labs');
  if (!mount) return;
  const csrf = mount.dataset.csrf || '';
  const MB = 1024 * 1024;
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

  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  };
  const count = (n, noun) => `${n} ${noun}${n === 1 ? '' : 's'}`;
  const date = (ts) => {
    if (!ts) return 'Not yet';
    const d = new Date(ts * 1000);
    return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
  };
  const size = (bytes) => {
    const mb = bytes / MB;
    return mb < 10 ? `${mb.toFixed(1)} MB` : `${Math.round(mb)} MB`;
  };

  async function call(method, path, body) {
    const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
    if (body) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify({ ...body, csrf });
    }
    const res = await fetch(path, init);
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) throw new Error(data?.detail || 'The node did not do this. Try again.');
    return data;
  }

  function facts(rows) {
    return el(
      'table',
      { class: 'ag-node-facts' },
      rows.map(([k, v]) => el('tr', {}, el('th', {}, k), el('td', {}, v))),
    );
  }

  function lab(row, refresh) {
    const error = el('p', { class: 'ag-node-warn', role: 'alert' });
    const quotaId = `quota-${row.lab_id}`;
    const quota = el('input', {
      class: 'rf-ui-input',
      id: quotaId,
      type: 'number',
      min: 1,
      step: 1,
      value: Math.round(row.quota / MB),
    });
    const run = (button, busy, body) => async (event) => {
      event.preventDefault();
      if (button.getAttribute('aria-disabled') === 'true') return;
      const label = button.textContent;
      button.textContent = busy;
      button.setAttribute('aria-disabled', 'true');
      error.textContent = '';
      try {
        await call('POST', `/admin/api/labs/${encodeURIComponent(row.lab_id)}`, body());
        await refresh();
      } catch (err) {
        error.textContent = err.message;
        button.textContent = label;
        button.removeAttribute('aria-disabled');
      }
    };
    const setQuota = el('button', { class: 'rf-ui-button rf-ui-button--secondary', type: 'submit' }, 'Set the limit');
    const toggle = el(
      'button',
      { class: 'rf-ui-button rf-ui-button--secondary', type: 'button' },
      row.suspended ? 'Allow changes' : 'Make read-only',
    );
    toggle.addEventListener(
      'click',
      run(toggle, 'Saving…', () => ({ suspended: !row.suspended })),
    );
    const form = el(
      'form',
      {
        class: 'ag-node-form',
        onsubmit: run(setQuota, 'Saving…', () => ({ quota: Math.max(1, Math.round(Number(quota.value))) * MB })),
      },
      el(
        'div',
        { class: 'ag-node-inline' },
        el('p', { class: 'rf-ui-field' }, el('label', { for: quotaId }, 'Space limit in MB'), quota),
        setQuota,
      ),
    );
    const summary = [row.name, count(row.members, 'member')];
    if (row.suspended) summary.push('read-only');
    return el(
      'details',
      { class: 'ag-node-more', 'data-lab': row.lab_id },
      el('summary', {}, summary.join(', ')),
      facts([
        ['Started', date(row.created_at)],
        ['PI and admins', row.admins],
        ['Lab space', `${size(row.bytes)} of ${size(row.quota)}, ${count(row.records, 'record')}`],
        ['Open invite links', row.open_invites],
        ['Last change', date(row.last_change_at)],
        ['Changes', row.suspended ? 'Read-only. Members read; nobody adds to the lab space.' : 'Open'],
      ]),
      form,
      el('div', { class: 'ag-node-inline' }, toggle),
      error,
    );
  }

  async function refresh() {
    const open = new Set([...mount.querySelectorAll('details[open]')].map((d) => d.dataset.lab));
    const rows = await call('GET', '/admin/api/labs');
    const list = rows.length ? rows.map((r) => lab(r, refresh)) : [el('p', { class: 'ag-node-empty' }, 'No labs yet.')];
    for (const d of list) if (d.dataset && open.has(d.dataset.lab)) d.open = true;
    mount.replaceChildren(...list);
  }

  refresh().catch(() => {
    /* the plain list of the page stays */
  });
})();
