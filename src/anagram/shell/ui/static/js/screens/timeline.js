// Timeline (track R4, step 15b): what the library learned, week by week,
// newest week first (`GET /api/timeline`). Each week: a short summary with a
// number after each statement when a model is set up (each number opens its
// item), then the findings, results, and methods as rows, then one line with
// the count of the other items. The lists come from the library with no model.
// A summary that the model writes after the first load arrives on
// `timeline.changed` and fades in (recipe S1).
import { html, useLayoutEffect, useRef, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { cleanText, fmtDate } from '../core/format.js';
import { optional, useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { Button, Empty, KindLabel, Row, RowList, Screen, StatusLine } from '../components/index.js';
import { ALL, PlaceSelect, placeName, useAskSetup } from '../parts/ask.js';

const WEEKS = 12;
// The order of the other kinds in the count line.
const OTHERS = ['note', 'draft', 'plan', 'data', 'code', 'correspondence', 'reference', 'admin', 'unknown'];

function day(d) {
  return d.toISOString().slice(0, 10);
}

/** The Monday `weeks - 1` weeks before this week, as `since`. */
function since(weeks) {
  const now = new Date();
  const monday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  monday.setUTCDate(monday.getUTCDate() - ((monday.getUTCDay() + 6) % 7) - 7 * (weeks - 1));
  return day(monday);
}

/** The summary text with each [n] as a link to its item. */
function Summary({ week }) {
  const ref = useRef(null);
  const first = useRef(true);
  useLayoutEffect(() => {
    // Only a summary that arrives while the screen is open fades in.
    if (!first.current && ref.current) ref.current.classList.add('ag-m-swap');
    first.current = false;
  }, [week.summary]);
  if (!week.summary) {
    return week.pending ? html`<${StatusLine} state="pending" text=${t('timeline.writing')} />` : null;
  }
  const cited = new Map((week.citations || []).map((c) => [c.n, c]));
  const parts = week.summary.split(/(\[\d+\])/);
  return html`
    <p class="ag-week-summary" ref=${ref}>
      ${parts.map((part, i) => {
        const m = /^\[(\d+)\]$/.exec(part);
        const c = m ? cited.get(Number(m[1])) : null;
        if (!c) return part;
        return html`<a key=${i} class="ag-cite" href=${href('item', { id: c.item_ref })}
          aria-label=${t('timeline.cite', { title: cleanText(c.title) || t('timeline.untitled') })}>${c.n}</a>`;
      })}
    </p>`;
}

function rowsOf(week) {
  return [...week.findings, ...week.results, ...week.methods];
}

function othersList(counts) {
  return OTHERS.filter((k) => counts[k])
    .map((k) => t(`timeline.count_${k}`, { n: counts[k] }))
    .join(', ');
}

function Others({ counts }) {
  const list = othersList(counts);
  if (!list) return null;
  return html`<p class="rf-ui-help ag-week-others">${t('timeline.also', { list })}</p>`;
}

/** A week with no finding, result, method, or summary: one quiet line. */
function QuietWeek({ week }) {
  return html`<p class="ag-week-quiet">${t('timeline.quiet', { date: fmtDate(week.start), list: othersList(week.counts) })}</p>`;
}

function Week({ week, spaces, many }) {
  const id = `week-${week.week}`;
  const rows = rowsOf(week);
  return html`
    <section class="ag-week" aria-labelledby=${id}>
      <h2 class="ag-section ag-week-title" id=${id}>${t('timeline.week_of', { date: fmtDate(week.start) })}</h2>
      <${Summary} week=${week} />
      <${RowList} items=${rows} keyOf=${(r) => r.item_ref} label=${t('timeline.week_of', { date: fmtDate(week.start) })}
        render=${(r) => html`
          <${Row} title=${cleanText(r.title) || t('timeline.untitled')}
            meta=${[
              r.stamped ? t('timeline.stamped') : html`<${KindLabel} kind=${r.kind} />`,
              many ? placeName(spaces, r.space) : null,
              fmtDate(r.time),
            ]
              .filter(Boolean)
              .flatMap((x, i) => (i ? [', ', x] : [x]))}
            note=${r.claim ? cleanText(r.claim) : null}
            href=${href('item', { id: r.item_ref })} />`} />
      <${Others} counts=${week.counts} />
    </section>`;
}

function View() {
  const setup = useAskSetup();
  const [space, setSpace] = useState(ALL);
  const [weeks, setWeeks] = useState(WEEKS);
  const query = new URLSearchParams({ since: since(weeks), ...(space !== ALL ? { space } : {}) });
  const timeline = useResource(`/api/timeline?${query}`, {
    topics: [['timeline', 'changed'].join('.'), 'item.kind', 'source.progress'],
    throttle: 2000,
  });
  // A new place or more weeks is a new path: the old weeks stay until the new ones are here.
  const last = useRef(null);
  if (timeline.data.value) last.current = timeline.data.value;
  return html`
    <${Screen} title=${t('timeline.title')} resources=${last.current ? [setup] : [setup, timeline]}>
      ${() => {
        const info = optional(setup);
        const list = timeline.data.value || last.current || [];
        const spaces = info.spaces || [];
        const many = space === ALL && spaces.length > 1;
        const shown = list.filter((w) => rowsOf(w).length || w.summary || Object.keys(w.counts).length);
        return html`
          <${PlaceSelect} id="timeline-space" spaces=${spaces} value=${space} onChange=${setSpace} />
          ${
            shown.length
              ? shown.map((w) =>
                  rowsOf(w).length || w.summary || w.pending
                    ? html`<${Week} key=${w.week} week=${w} spaces=${spaces} many=${many} />`
                    : html`<${QuietWeek} key=${w.week} week=${w} />`,
                )
              : html`<${Empty} text=${t('timeline.empty', { n: weeks })} />`
          }
          <div class="rf-ui-actions ag-week-more">
            <${Button} kind="secondary" onClick=${() => setWeeks(weeks + WEEKS)}>${t('timeline.earlier')}<//>
          </div>`;
      }}
    <//>`;
}

export const screen = { id: 'timeline', path: '/timeline', nav: { group: 'main', order: 25 }, View };
