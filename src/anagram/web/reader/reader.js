// The reading view of a shared finding.
//
//   import { mountReader } from '/reader/reader.js';
//   const view = mountReader(element, model, {
//     file: (item) => url of the original file of the item,
//     figure: (item, figure) => url of one figure of the reading copy,
//   });
//   view.show(index); view.destroy();
//
// `model` is the reading model returned by `open_received`. The
// view needs no framework, so that the member app and a later node page can
// use the same files. Content goes into the page as text nodes only.

import { el, clear, reducedMotion } from './dom.js';
import { flow, grid, code, inline } from './blocks.js';
import { pdfView } from './pdfview.js';
import { WORDS, say } from './words.js';

const SUFFIX = /\.([A-Za-z0-9]{1,8})$/;
const INLINE_VIEWS = new Set(['pdf', 'image', 'text']);

function suffix(name) {
  const m = String(name || '').match(SUFFIX);
  return m ? m[1].toLowerCase() : '';
}

export function formatBytes(words, size) {
  const n = Number(size) || 0;
  const one = (value) => (value >= 10 ? Math.round(value) : Math.round(value * 10) / 10);
  if (n < 1000) return say(words, 'bytes.b', { n });
  if (n < 1e6) return say(words, 'bytes.kb', { n: one(n / 1e3) });
  if (n < 1e9) return say(words, 'bytes.mb', { n: one(n / 1e6) });
  return say(words, 'bytes.gb', { n: one(n / 1e9) });
}

// A date with no time is a UTC day (a proof day). A time shows the day of
// this computer, as in the app (core/format.js, fmtDate).
export function formatDate(words, iso) {
  if (!iso) return '';
  const day = String(iso).length === 10;
  const d = new Date(day ? `${iso}T00:00:00Z` : iso);
  if (Number.isNaN(d.getTime())) return '';
  if (day) return `${d.getUTCDate()} ${words.months[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
  return `${d.getDate()} ${words.months[d.getMonth()]} ${d.getFullYear()}`;
}

const count = (n) => Number(n).toLocaleString('en-GB');

/** The word for the kind of an item: a notebook and source code have their own. */
function kindOf(words, item) {
  const ext = suffix(item.name);
  if (ext === 'ipynb') return say(words, 'kinds.notebook');
  if (item.view === 'text' && !['md', 'markdown', 'txt'].includes(ext)) return say(words, 'kinds.code');
  if (item.view === 'pdf') return say(words, 'kinds.pdf');
  return say(words, `kinds.${item.view}`);
}

function slideGroups(blocks) {
  const groups = [];
  let current = null;
  for (const block of blocks || []) {
    if (block.kind === 'slide') {
      current = { anchor: block.anchor, blocks: [] };
      groups.push(current);
    } else {
      if (!current) {
        current = { anchor: null, blocks: [] };
        groups.push(current);
      }
      current.blocks.push(block);
    }
  }
  return groups.filter((g) => g.anchor || g.blocks.length);
}

/** The short line under a file name: kind, then size or count. */
function metaLine(words, item, extra) {
  const parts = [kindOf(words, item)];
  if (extra) parts.push(extra);
  else if (item.view === 'table' && item.table) {
    parts.push(say(words, 'rows', { n: item.table.total_rows, count: count(item.table.total_rows) }));
  } else if (item.view === 'slides') {
    const n = slideGroups(item.blocks).length;
    if (n) parts.push(say(words, 'slides_n', { n }));
  }
  parts.push(formatBytes(words, item.size));
  return parts.join(' · ');
}

function figureNode(source, item, figure, caption) {
  const img = el('img', { src: source.figure(item, figure), alt: caption, loading: 'lazy', decoding: 'async' });
  return el('figure', { class: 'rd-figure' }, el('div', { class: 'rd-mat' }, img), el('figcaption', {}, caption));
}

function gallery(words, source, item, figures) {
  if (!figures.length) return [];
  return [
    el(
      'section',
      { class: 'rd-gallery', 'aria-label': say(words, 'figures') },
      el('h3', { class: 'rd-h rd-h3' }, say(words, 'figures')),
      el(
        'div',
        { class: 'rd-gallery-grid' },
        figures.map((f, n) => figureNode(source, item, f, say(words, 'figure_n', { n: n + 1 }))),
      ),
    ),
  ];
}

function truncatedNote(words, item) {
  return item.truncated ? el('p', { class: 'rd-note' }, say(words, 'truncated')) : null;
}

// ------------------------------------------------------------- the views

function documentView(words, source, item) {
  const figures = item.figures || [];
  const placed = new Set();
  const isNotebook = suffix(item.name) === 'ipynb';
  const after = (block) => {
    if (!isNotebook || block.kind !== 'code') return [];
    const mine = figures.filter((f) => f.id.startsWith(`${block.anchor}-`));
    for (const f of mine) placed.add(f.id);
    return mine.map((f) =>
      el(
        'div',
        { class: 'rd-output' },
        el('p', { class: 'rd-output-label' }, say(words, 'output')),
        figureNode(source, item, f, say(words, 'figure_n', { n: figures.indexOf(f) + 1 })),
      ),
    );
  };
  const body = flow(item.blocks, {
    after,
    pageLabel: (b) => say(words, 'page_label', { n: Number(String(b.anchor).split('-')[1]) || '' }),
  });
  const rest = figures.filter((f) => !placed.has(f.id));
  const prose = el('div', { class: isNotebook ? 'rd-prose rd-prose--notebook' : 'rd-prose' }, body);
  if (!body.length) prose.append(el('p', { class: 'rd-note' }, say(words, 'empty_item')));
  return { node: el('div', {}, prose, gallery(words, source, item, rest), truncatedNote(words, item)) };
}

function textView(words, source, item) {
  const blocks = item.blocks || [];
  const ext = suffix(item.name);
  if (!['md', 'markdown'].includes(ext) && blocks.length === 1 && blocks[0].kind === 'code') {
    return { node: el('div', { class: 'rd-source' }, code(blocks[0].text, { numbers: true, label: item.name })) };
  }
  return documentView(words, source, item);
}

function slidesView(words, source, item) {
  const groups = slideGroups(item.blocks);
  const total = groups.length;
  const cards = groups.map((group, i) => {
    const blocks = [...group.blocks];
    let title = null;
    const h = blocks.findIndex((b) => b.kind === 'heading');
    if (h >= 0) title = blocks.splice(h, 1)[0].text;
    else if (blocks[0]?.kind === 'para') {
      const [first, ...more] = blocks[0].text.split('\n');
      title = first;
      if (more.length) blocks[0] = { ...blocks[0], text: more.join('\n') };
      else blocks.shift();
    }
    return el(
      'section',
      { class: 'rd-slide', 'aria-label': say(words, 'slide_of', { n: i + 1, total }) },
      el('p', { class: 'rd-slide-num' }, String(i + 1)),
      title ? el('h3', { class: 'rd-slide-title' }, inline(title)) : null,
      el('div', { class: 'rd-slide-body' }, flow(blocks)),
    );
  });
  const node = el(
    'div',
    {},
    el('div', { class: 'rd-slides' }, cards),
    cards.length ? null : el('p', { class: 'rd-note' }, say(words, 'empty_item')),
    gallery(words, source, item, item.figures || []),
    truncatedNote(words, item),
  );
  return { node, step: (dir) => stepThrough(cards, dir) };
}

/** Scroll to the next or the previous element of a list. */
function stepThrough(nodes, dir) {
  if (!nodes.length) return false;
  let current = 0;
  nodes.forEach((n, i) => {
    if (n.getBoundingClientRect().top <= window.innerHeight * 0.25) current = i;
  });
  const first = nodes[0].getBoundingClientRect().top > window.innerHeight * 0.25;
  const next = first && dir > 0 ? 0 : Math.max(0, Math.min(nodes.length - 1, current + dir));
  if (!first && next === current) return false;
  nodes[next].scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
  return true;
}

function tableView(words, _source, item) {
  const t = item.table || { columns: [], rows: [], total_rows: 0 };
  const note =
    t.total_rows > t.rows.length
      ? el(
          'p',
          { class: 'rd-note' },
          say(words, 'rows_shown', { shown: count(t.rows.length), total: count(t.total_rows) }),
        )
      : null;
  return {
    node: el('div', { class: 'rd-tableview' }, grid(t.columns, t.rows, { rowNumbers: true, label: item.name }), note),
  };
}

function imageView(_words, source, item) {
  const img = el('img', { src: source.file(item), alt: item.name, decoding: 'async' });
  const size = el('span', { class: 'rd-dim' });
  img.addEventListener('load', () => {
    if (img.naturalWidth) size.textContent = `${count(img.naturalWidth)} × ${count(img.naturalHeight)}`;
  });
  return {
    node: el(
      'figure',
      { class: 'rd-figure rd-figure--main' },
      el('a', { class: 'rd-mat', href: source.file(item), target: '_blank', rel: 'noopener' }, img),
      el('figcaption', {}, size),
    ),
  };
}

function fileView(words, source, item) {
  return {
    node: el(
      'div',
      { class: 'rd-filecard' },
      el('p', { class: 'rd-filecard-text' }, say(words, 'no_preview')),
      el('a', { class: 'rd-button', href: source.file(item), download: item.name }, say(words, 'save_copy')),
    ),
  };
}

function pdfItemView(words, source, item, meta) {
  const holder = el('div', {});
  const view = pdfView(source.file(item), words, {
    name: item.name,
    onReady: ({ pages, layout }) => {
      meta.textContent = metaLine(words, item, say(words, layout === 'slides' ? 'slides_n' : 'pages', { n: pages }));
    },
    onFail: () => {
      holder.dataset.state = 'failed';
      const text = flow(item.blocks || []);
      holder.replaceChildren(
        el('p', { class: 'rd-note' }, say(words, text.length ? 'pdf_failed' : 'pdf_failed_empty')),
        ...(text.length ? [el('div', { class: 'rd-prose' }, text)] : []),
      );
    },
  });
  holder.append(view.node);
  return { node: holder, step: view.step, destroy: view.destroy };
}

const VIEWS = {
  pdf: pdfItemView,
  image: imageView,
  table: tableView,
  text: textView,
  document: documentView,
  slides: slidesView,
  file: fileView,
};

// ------------------------------------------------------------- the frame

function factsList(words, model) {
  const rows = [];
  const add = (term, value) => {
    if (value) rows.push(el('div', { class: 'rd-fact' }, el('dt', {}, term), el('dd', {}, value)));
  };
  if (model.version) add(say(words, 'version'), String(model.version));
  add(say(words, 'proven'), formatDate(words, model.proven_by));
  const details = model.root
    ? el(
        'details',
        { class: 'rd-details' },
        el('summary', {}, say(words, 'details')),
        el('p', {}, say(words, 'root')),
        el('code', { class: 'rd-root' }, String(model.root)),
      )
    : null;
  return el(
    'aside',
    { class: 'rd-facts', 'aria-label': say(words, 'facts') },
    el('h2', { class: 'rd-label' }, say(words, 'facts')),
    el('dl', {}, rows),
    el('p', { class: 'rd-proof' }, say(words, model.verified ? 'checked' : 'not_checked')),
    details,
  );
}

function splitClaim(model) {
  const claim = String(model.claim || '').trim();
  const lines = claim.split('\n');
  const title = (model.title || lines[0] || '').trim();
  const rest = lines[0].trim() === title ? lines.slice(1).join('\n').trim() : claim;
  return { title, rest: rest === title ? '' : rest };
}

/** Mount the reading view of `model` into `root`. */
export function mountReader(root, model, source, { words = WORDS } = {}) {
  const items = Array.isArray(model.items) ? model.items : [];
  const { title, rest } = splitClaim(model);
  const many = items.length > 1;
  let current = -1;
  let view = null;

  clear(root);
  root.classList.add('rd');
  root.dataset.items = String(items.length);

  const head = el(
    'header',
    { class: 'rd-head' },
    el(
      'p',
      { class: 'rd-label' },
      say(words, model.granted_at ? 'byline_on' : 'byline', {
        name: model.owner?.label || say(words, 'a_member'),
        date: formatDate(words, model.granted_at),
      }),
    ),
    el('h1', { class: 'rd-title' }, title),
    rest ? el('p', { class: 'rd-lede' }, rest) : null,
  );
  const children = model.set?.children?.length || 0;
  if (children) head.append(el('p', { class: 'rd-note' }, say(words, 'includes', { n: children })));

  const buttons = items.map((item, i) =>
    el(
      'button',
      { type: 'button', class: 'rd-toc-item', 'data-index': i },
      el('span', { class: 'rd-toc-name' }, item.name),
      el('span', { class: 'rd-toc-kind' }, kindOf(words, item)),
    ),
  );
  const toc = many
    ? el(
        'nav',
        { class: 'rd-toc', 'aria-label': say(words, 'contents') },
        el('h2', { class: 'rd-label' }, say(words, 'contents')),
        el(
          'ol',
          {},
          buttons.map((b) => el('li', {}, b)),
        ),
      )
    : null;
  buttons.forEach((b, i) => {
    b.addEventListener('click', () => show(i, { focus: true }));
  });

  const stage = el('article', { class: 'rd-item', 'aria-live': 'off' });
  const layout = el(
    'div',
    { class: many ? 'rd-layout' : 'rd-layout rd-layout--one' },
    toc,
    stage,
    factsList(words, model),
  );
  root.append(head, layout);

  function show(i, { focus = false } = {}) {
    if (i === current || i < 0 || i >= items.length) return;
    view?.destroy?.();
    current = i;
    const item = items[i];
    buttons.forEach((b, n) => {
      if (n === i) b.setAttribute('aria-current', 'true');
      else b.removeAttribute('aria-current');
    });
    const meta = el('p', { class: 'rd-meta' }, metaLine(words, item));
    const inlineOpen = INLINE_VIEWS.has(item.view);
    const action =
      item.view === 'file'
        ? null
        : el(
            'a',
            {
              class: 'rd-action',
              href: source.file(item),
              target: inlineOpen ? '_blank' : null,
              rel: inlineOpen ? 'noopener' : null,
              download: inlineOpen ? null : item.name,
            },
            say(words, inlineOpen ? 'open_original' : 'save_copy'),
          );
    const heading = el('h2', { class: 'rd-item-title', tabindex: '-1' }, item.name);
    const make = VIEWS[item.view] || fileView;
    view = make(words, source, item, meta);
    const next = items[i + 1];
    const onward = next
      ? el(
          'p',
          { class: 'rd-onward' },
          el('button', { type: 'button', class: 'rd-link' }, say(words, 'next_file', { name: next.name })),
        )
      : null;
    onward?.firstChild.addEventListener('click', () => show(i + 1, { focus: true }));
    stage.dataset.view = item.view;
    stage.replaceChildren(
      ...[
        el('header', { class: 'rd-item-head' }, el('div', {}, heading, meta), action),
        el('div', { class: 'rd-item-body' }, view.node),
        onward,
      ].filter(Boolean),
    );
    buttons[i]?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    stage.classList.remove('rd-enter');
    void stage.offsetWidth; // restart the entry motion
    stage.classList.add('rd-enter');
    if (focus) {
      heading.focus({ preventScroll: true });
      if (stage.getBoundingClientRect().top < 0) {
        stage.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
      }
    }
  }

  const onKey = (event) => {
    if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    const target = event.target;
    if (
      target instanceof Element &&
      target.closest('input, textarea, select, [contenteditable], .rd-grid, pre, .textLayer')
    )
      return;
    if (view?.step?.(event.key === 'ArrowRight' ? 1 : -1)) event.preventDefault();
  };
  document.addEventListener('keydown', onKey);

  if (items.length) show(0);
  else stage.append(el('p', { class: 'rd-note' }, say(words, 'empty')));
  root.dataset.state = 'ready';

  return {
    show: (i) => show(i, { focus: true }),
    get current() {
      return current;
    },
    destroy() {
      document.removeEventListener('keydown', onKey);
      view?.destroy?.();
      clear(root);
    },
  };
}
