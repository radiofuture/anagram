// Blocks of a reading copy (`Block.to_json()`: heading, para, table, slide,
// page, code) as DOM. Markdown marks inside a block become text styles. No
// HTML of the content is parsed: a tag in the text shows as text.

import { el, safeHref } from './dom.js';

const INLINE = new RegExp(
  [
    '(`[^`\\n]+`)', // 1 code
    '(!?\\[[^\\]\\n]*\\]\\([^)\\s]*\\))', // 2 link or image
    '(\\*\\*[^*\\n]+\\*\\*|__[^_\\n]+__)', // 3 strong
    '(\\*[^*\\s][^*\\n]*\\*|(?<![\\w])_[^_\\s][^_\\n]*_(?![\\w]))', // 4 emphasis
    '(https?://[^\\s<>()\\[\\]]+[^\\s<>()\\[\\].,;:!?\'"])', // 5 bare URL
  ].join('|'),
  'g',
);

/** Inline Markdown as nodes. */
export function inline(text) {
  const out = [];
  let last = 0;
  for (const m of String(text).matchAll(INLINE)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    const [whole, code, link, strong, em, url] = m;
    if (code) out.push(el('code', {}, code.slice(1, -1)));
    else if (link) {
      const parts = link.match(/^(!?)\[([^\]]*)\]\(([^)]*)\)$/);
      const label = parts[2] || parts[3];
      const href = parts[1] ? null : safeHref(parts[3]);
      // An image in the text is not loaded: its words show.
      out.push(href ? outLink(href, inline(label)) : parts[1] ? el('span', { class: 'rd-alt' }, label) : label);
    } else if (strong) out.push(el('strong', {}, inline(strong.slice(2, -2))));
    else if (em) out.push(el('em', {}, inline(em.slice(1, -1))));
    else if (url) {
      const href = safeHref(url);
      out.push(href ? outLink(href, url) : url);
    } else out.push(whole);
    last = m.index + whole.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function outLink(href, children) {
  return el('a', { href, target: '_blank', rel: 'noopener noreferrer nofollow' }, children);
}

const BULLET = /^\s{0,3}([-*+•])\s+(.*)$/;
const NUMBER = /^\s{0,3}(\d{1,4})[.)]\s+(.*)$/;
const QUOTE = /^\s{0,3}>\s?(.*)$/;

/** A paragraph block: lists, quotes, and line breaks keep their shape. */
export function para(text) {
  const lines = String(text).split('\n');
  const nodes = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (BULLET.test(line) || NUMBER.test(line)) {
      const ordered = NUMBER.test(line);
      const pattern = ordered ? NUMBER : BULLET;
      const first = ordered ? Number(line.match(NUMBER)[1]) : null;
      const list = el(ordered ? 'ol' : 'ul', { class: 'rd-list', start: ordered && first !== 1 ? first : null });
      while (i < lines.length && pattern.test(lines[i])) {
        const item = el('li', {}, inline(lines[i].match(pattern)[2]));
        i += 1;
        // A line with no mark after an item continues that item.
        while (
          i < lines.length &&
          lines[i].trim() &&
          !BULLET.test(lines[i]) &&
          !NUMBER.test(lines[i]) &&
          !QUOTE.test(lines[i])
        ) {
          item.append(' ', ...inline(lines[i].trim()));
          i += 1;
        }
        list.append(item);
      }
      nodes.push(list);
    } else if (QUOTE.test(line)) {
      const quote = el('blockquote', { class: 'rd-quote' });
      const parts = [];
      while (i < lines.length && QUOTE.test(lines[i])) {
        parts.push(lines[i].match(QUOTE)[1]);
        i += 1;
      }
      quote.append(...lineBreaks(parts));
      nodes.push(quote);
    } else {
      const parts = [];
      while (i < lines.length && !BULLET.test(lines[i]) && !NUMBER.test(lines[i]) && !QUOTE.test(lines[i])) {
        parts.push(lines[i]);
        i += 1;
      }
      nodes.push(el('p', { class: 'rd-p' }, lineBreaks(parts)));
    }
  }
  return nodes;
}

function lineBreaks(parts) {
  const out = [];
  parts.forEach((part, n) => {
    if (n) out.push(el('br'));
    out.push(...inline(part));
  });
  return out;
}

/** A Markdown pipe table as rows of cells. The separator row goes. */
export function pipeRows(text) {
  const rows = [];
  for (const raw of String(text).split('\n')) {
    let line = raw.trim();
    if (!line) continue;
    if (line.startsWith('|')) line = line.slice(1);
    if (line.endsWith('|') && !line.endsWith('\\|')) line = line.slice(0, -1);
    const cells = line.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
    if (cells.every((c) => /^:?-{2,}:?$/.test(c))) continue;
    rows.push(cells);
  }
  // A converter can give an empty first row when the file has no header row.
  while (rows.length > 1 && rows[0].every((c) => !c)) rows.shift();
  return rows;
}

const NUMERIC = /^[-+−]?(\d{1,3}(,\d{3})+|\d+)?(\.\d+)?([eE][-+]?\d+)?\s?%?$/;

/** True if the column has numbers only (empty cells do not count). */
export function numericColumn(rows, index) {
  let seen = 0;
  for (const row of rows) {
    const cell = (row[index] ?? '').trim();
    if (!cell) continue;
    if (!NUMERIC.test(cell) || !/\d/.test(cell)) return false;
    seen += 1;
  }
  return seen > 0;
}

/** A grid with a fixed header row. `rows` has no header. */
export function grid(columns, rows, { caption, rowNumbers = false, label } = {}) {
  const width = Math.max(columns.length, ...rows.map((r) => r.length), 0);
  const numeric = Array.from({ length: width }, (_, c) => numericColumn(rows, c));
  const head = el(
    'tr',
    {},
    rowNumbers ? el('th', { class: 'rd-rownum', scope: 'col' }, el('span', { class: 'rd-sr' }, '#')) : null,
    Array.from({ length: width }, (_, c) =>
      el('th', { scope: 'col', class: numeric[c] ? 'rd-num' : null }, inline(columns[c] ?? '')),
    ),
  );
  const body = el(
    'tbody',
    {},
    rows.map((row, r) =>
      el(
        'tr',
        {},
        rowNumbers ? el('th', { class: 'rd-rownum', scope: 'row' }, String(r + 1)) : null,
        Array.from({ length: width }, (_, c) =>
          el('td', { class: numeric[c] ? 'rd-num' : null }, inline(row[c] ?? '')),
        ),
      ),
    ),
  );
  const table = el(
    'table',
    { class: 'rd-table' },
    caption ? el('caption', { class: 'rd-sr' }, caption) : null,
    el('thead', {}, head),
    body,
  );
  // The scroll box can take focus, so that a keyboard can scroll it.
  return el('div', { class: 'rd-grid', tabindex: '0', role: 'region', 'aria-label': label || caption || null }, table);
}

/** A code block. `numbers`: line numbers (a source file). */
export function code(text, { numbers = false, label = null } = {}) {
  const lines = String(text).replace(/\n$/, '').split('\n');
  const block = el('pre', { class: numbers ? 'rd-code rd-code--lines' : 'rd-code', tabindex: '0' });
  if (label) block.setAttribute('aria-label', label);
  const body = el('code', {});
  if (numbers) {
    lines.forEach((line, n) => {
      body.append(
        el(
          'span',
          { class: 'rd-line' },
          el('span', { class: 'rd-ln', 'aria-hidden': 'true' }, String(n + 1)),
          line || ' ',
        ),
      );
    });
  } else body.append(lines.join('\n'));
  block.append(body);
  return block;
}

/** Heading level of a block: the item name is h2, so the text starts at h3. */
export function heading(block) {
  const level = Math.min(6, Math.max(3, (block.level || 1) + 2));
  return el(`h${level}`, { class: `rd-h rd-h${Math.min(level, 5)}`, id: null }, inline(block.text));
}

/**
 * The flow of blocks as nodes. `after(block)` can give nodes that go after a
 * block (the figures of a notebook cell).
 */
export function flow(blocks, { after = () => [], pageLabel = null, codeLabel = null } = {}) {
  const out = [];
  for (const block of blocks || []) {
    switch (block.kind) {
      case 'heading':
        out.push(heading(block));
        break;
      case 'para':
        out.push(...para(block.text));
        break;
      case 'table': {
        const rows = pipeRows(block.text);
        if (rows.length) out.push(grid(rows[0], rows.slice(1)));
        break;
      }
      case 'code':
        out.push(code(block.text, { label: codeLabel }));
        break;
      case 'page':
        if (pageLabel) out.push(el('p', { class: 'rd-pagemark', 'aria-hidden': 'true' }, pageLabel(block)));
        break;
      case 'slide':
        break;
      default:
        if (block.text) out.push(el('p', { class: 'rd-p' }, inline(block.text)));
    }
    out.push(...after(block));
  }
  return out;
}
