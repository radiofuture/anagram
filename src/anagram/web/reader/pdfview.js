// The PDF view of the reading view: the original file, page by page, with
// pdf.js (vendored, see the manifest next to it). This is the only module of
// the reader that loads the vendored files.
//
// Safety: the PDF is data. pdf.js runs no script of the PDF (no scripting,
// no XFA, no eval). Pages are canvas images with a text layer of text nodes.

import { el, clear, reducedMotion } from './dom.js';
import { say } from './words.js';

const LIB = new URL('vendor/pdf.min.mjs', import.meta.url).href;
const WORKER = new URL('vendor/pdf.worker.min.mjs', import.meta.url).href;
const MAX_SCALE = 3;

let lib = null;

async function pdfjs() {
  if (!lib) {
    lib = import(LIB).then((mod) => {
      mod.GlobalWorkerOptions.workerSrc = WORKER;
      return mod;
    });
  }
  return lib;
}

async function openPdf(url) {
  const [mod, response] = await Promise.all([pdfjs(), fetch(url, { credentials: 'same-origin' })]);
  if (!response.ok) throw new Error(`fetch ${response.status}`);
  const data = new Uint8Array(await response.arrayBuffer());
  const task = mod.getDocument({
    data,
    isEvalSupported: false,
    enableXfa: false,
    disableAutoFetch: true,
    stopAtErrors: false,
  });
  return { mod, task, doc: await task.promise };
}

/** Draw one page into `box` at the width of the box. Returns the scale. */
async function drawPage(mod, page, box, state) {
  const base = page.getViewport({ scale: 1 });
  const width = Math.max(box.clientWidth, 240);
  const scale = Math.min(MAX_SCALE, width / base.width);
  const viewport = page.getViewport({ scale });
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const canvas = el('canvas', { class: 'rd-canvas', role: 'img', 'aria-label': state.label });
  canvas.width = Math.floor(viewport.width * ratio);
  canvas.height = Math.floor(viewport.height * ratio);
  const layer = el('div', { class: 'textLayer' });
  box.style.setProperty('--scale-factor', String(scale));
  box.style.aspectRatio = `${base.width} / ${base.height}`;
  const task = page.render({
    canvas,
    canvasContext: canvas.getContext('2d'),
    viewport,
    transform: ratio === 1 ? null : [ratio, 0, 0, ratio, 0, 0],
  });
  state.task = task;
  await task.promise;
  if (state.gone) return scale;
  clear(box);
  box.append(canvas, layer);
  box.dataset.drawn = 'true';
  state.width = width;
  state.baseWidth = base.width;
  try {
    const text = new mod.TextLayer({
      textContentSource: page.streamTextContent({ includeMarkedContent: true, disableNormalization: true }),
      container: layer,
      viewport,
    });
    await text.render();
  } catch {
    // Text selection is a help; the page shows without it.
  }
  return scale;
}

/**
 * The view of one PDF item. `onFail()` is called when the file does not
 * open; the caller shows the text of the reading copy instead.
 */
export function pdfView(url, words, { name, onFail, onReady } = {}) {
  const root = el(
    'div',
    { class: 'rd-pdf', 'data-state': 'loading' },
    el('p', { class: 'rd-wait', role: 'status' }, say(words, 'loading_pdf')),
  );
  const life = { gone: false, task: null, observers: [], step: () => false };

  (async () => {
    let opened;
    try {
      opened = await openPdf(url);
    } catch {
      if (!life.gone) {
        root.dataset.state = 'failed';
        clear(root);
        onFail?.();
      }
      return;
    }
    life.task = opened.task;
    if (life.gone) {
      opened.task.destroy();
      return;
    }
    const first = await opened.doc.getPage(1);
    const base = first.getViewport({ scale: 1 });
    const slides = base.width > base.height * 1.15;
    clear(root);
    root.dataset.layout = slides ? 'slides' : 'pages';
    if (slides) slideLayout(opened, root, words, life, base, name);
    else pageLayout(opened, root, words, life, base, name);
    root.dataset.state = 'ready';
    onReady?.({ pages: opened.doc.numPages, layout: root.dataset.layout });
  })();

  return {
    node: root,
    step: (dir) => life.step(dir),
    destroy() {
      life.gone = true;
      for (const o of life.observers) o.disconnect();
      life.task?.destroy();
    },
  };
}

function pageLayout({ mod, doc }, root, words, life, base, name) {
  const total = doc.numPages;
  const boxes = [];
  const states = [];
  const list = el('ol', { class: 'rd-pages', 'aria-label': name || null });
  for (let n = 1; n <= total; n += 1) {
    const label = say(words, 'page_of', { n, total });
    const box = el('div', { class: 'rd-page', 'data-page': n });
    box.style.aspectRatio = `${base.width} / ${base.height}`;
    boxes.push(box);
    states.push({ label, gone: false, drawing: null, width: 0, baseWidth: base.width });
    list.append(
      el('li', { class: 'rd-page-wrap' }, box, el('p', { class: 'rd-page-num', 'aria-hidden': 'true' }, String(n))),
    );
  }
  root.append(list);

  const draw = (i) => {
    const state = states[i];
    if (state.drawing || life.gone) return;
    state.drawing = doc
      .getPage(i + 1)
      .then((page) => {
        state.gone = life.gone;
        return drawPage(mod, page, boxes[i], state);
      })
      .catch(() => {
        state.drawing = null;
      });
  };
  const seen = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) draw(boxes.indexOf(entry.target));
      }
    },
    { rootMargin: '800px 0px' },
  );
  for (const box of boxes) seen.observe(box);
  // The text layer follows the width of the page box (pdf.js uses this CSS
  // variable); a much wider box draws the canvas again.
  const sized = new ResizeObserver(() => {
    boxes.forEach((box, i) => {
      const state = states[i];
      if (!box.dataset.drawn) return;
      box.style.setProperty('--scale-factor', String(box.clientWidth / state.baseWidth));
      if (box.clientWidth > state.width * 1.3) {
        state.drawing = null;
        delete box.dataset.drawn;
        draw(i);
      }
    });
  });
  sized.observe(root);
  life.observers.push(seen, sized);

  life.step = (dir) => {
    const top = root.getBoundingClientRect().top;
    // The page that is at the top of the window now.
    let current = 0;
    boxes.forEach((box, i) => {
      if (box.getBoundingClientRect().top - top <= window.innerHeight * 0.1 + (top < 0 ? -top : 0)) current = i;
    });
    const next = Math.max(0, Math.min(total - 1, current + dir));
    if (next === current) return false;
    boxes[next].parentElement.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
    return true;
  };
}

function slideLayout({ mod, doc }, root, words, life, base, name) {
  const total = doc.numPages;
  let current = 1;
  const stage = el('div', { class: 'rd-stage', 'aria-label': name || null });
  const box = el('div', { class: 'rd-page rd-page--slide' });
  box.style.aspectRatio = `${base.width} / ${base.height}`;
  stage.append(box);
  const count = el('p', { class: 'rd-count', 'aria-live': 'polite' });
  // Word buttons in the link style of the reader: the text is the name.
  const prev = el('button', { type: 'button', class: 'rd-link rd-step' }, say(words, 'previous_slide'));
  const next = el('button', { type: 'button', class: 'rd-link rd-step' }, say(words, 'next_slide'));
  const controls = el('div', { class: 'rd-controls' }, prev, count, next);
  root.append(stage, controls);
  let state = null;

  const show = async (n) => {
    current = n;
    count.textContent = say(words, 'slide_of', { n, total });
    prev.disabled = n <= 1;
    next.disabled = n >= total;
    if (state) state.gone = true;
    state = { label: say(words, 'slide_label', { n }), gone: false, width: 0, baseWidth: base.width };
    const mine = state;
    const page = await doc.getPage(n);
    if (mine.gone || life.gone) return;
    const fresh = el('div', { class: 'rd-page rd-page--slide' });
    fresh.style.aspectRatio = box.style.aspectRatio;
    // Draw off screen, then change in one step (no empty frame).
    const holder = el('div', { class: 'rd-offstage', 'aria-hidden': 'true' }, fresh);
    stage.append(holder);
    fresh.style.width = `${stage.clientWidth}px`;
    await drawPage(mod, page, fresh, mine);
    holder.remove();
    fresh.style.width = '';
    if (mine.gone || life.gone) return;
    stage.replaceChildren(fresh);
    fresh.classList.add('rd-enter');
  };
  prev.addEventListener('click', () => current > 1 && show(current - 1));
  next.addEventListener('click', () => current < total && show(current + 1));
  const sized = new ResizeObserver(() => {
    const shown = stage.firstElementChild;
    if (shown?.dataset.drawn && state) {
      shown.style.setProperty('--scale-factor', String(shown.clientWidth / state.baseWidth));
    }
  });
  sized.observe(stage);
  life.observers.push(sized);
  life.step = (dir) => {
    const n = current + dir;
    if (n < 1 || n > total) return false;
    show(n);
    return true;
  };
  show(1);
}
