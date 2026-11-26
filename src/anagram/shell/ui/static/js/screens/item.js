// One item of the library: what Anagram read in it, and what it links to.
// R4 owns this screen after step 9b. The kind is a select: one choice
// corrects it (`PUT /api/items/{ref}/kind`). Other tracks
// add actions through the slot `item.actions` (share, put in the lab space).
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { baseName, cleanText, fmtDate } from '../core/format.js';
import { absent, mutate, optional, useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { extraText, polarityWord } from './library.js';
import { Empty, ErrorLine, Facts, Field, Row, RowList, Screen, Section, Slot } from '../components/index.js';

const SLOT = ['item', 'actions'].join('.');

/** The kind of the item, and the correction: one choice in a native select. */
function Kind({ item, kinds }) {
  const [shown, setShown] = useState(null); // the new kind while the save runs
  const [error, setError] = useState('');
  if (!kinds.length) return null;
  const value = shown || item.kind;
  const change = async (kind) => {
    setShown(kind);
    setError('');
    try {
      const path = `/api/items/${encodeURIComponent(item.ref)}`;
      await mutate('PUT', `${path}/kind`, { kind }, { invalidate: [path, '/api/kinds'] });
      announce(t('item.kind_saved', { kind: kinds.find((k) => k.id === kind)?.label }));
    } catch (err) {
      setError(err.message);
    }
    setShown(null);
  };
  return html`
    <div class="ag-item-kind">
      <${Field} id="item-kind" label=${t('item.kind')}>
        <select class="rf-ui-input" id="item-kind" value=${value} onChange=${(e) => change(e.currentTarget.value)}>
          ${kinds.map((k) => html`<option key=${k.id} value=${k.id}>${k.label}</option>`)}
        </select>
      <//>
      <${ErrorLine} text=${error} />
    </div>`;
}

function Body({ item, kinds }) {
  const claims = (item.claims || []).filter((c) => cleanText(c.text));
  const people = (item.people || []).map((p) => p.name).filter(Boolean);
  const names = (item.entities || []).map((e) => e.text).filter(Boolean);
  return html`
    ${extraText(item.title, item.summary) && html`<p class="ag-lead">${extraText(item.title, item.summary)}</p>`}
    <${Kind} item=${item} kinds=${kinds} />
    ${polarityWord(item) && html`<p class="rf-ui-help" data-testid="polarity">${polarityWord(item)}</p>`}
    <${Facts} rows=${[
      [t('item.source'), baseName(item.source_label)],
      [t('item.date'), item.time ? fmtDate(item.time) : null],
      [t('item.people'), people.join(', ')],
      [t('item.names'), names.slice(0, 12).join(', ')],
      [t('item.versions'), item.versions && item.versions.length > 1 ? String(item.versions.length) : null],
    ]} />
    <${Slot} name=${SLOT} props=${{ item }} />
    ${
      claims.length > 0 &&
      html`
      <${Section} id="claims-title" title=${t('item.claims')}>
        <ul class="ag-plain ag-claims">
          ${claims.map((c, i) => html`<li key=${i} class="ag-quote">${cleanText(c.text)}</li>`)}
        </ul>
      <//>`
    }
    ${
      item.links &&
      item.links.length > 0 &&
      html`
      <${Section} id="links-title" title=${t('item.links')}>
        <${RowList} items=${item.links} keyOf=${(l) => `${l.relation} ${l.ref}`} label=${t('item.links')}
          render=${(l) => html`<${Row} title=${cleanText(l.title) || t('library.untitled')}
            meta=${t(`item.relation_${l.relation}`)} href=${href('item', { id: l.ref })} />`} />
      <//>`
    }`;
}

function View({ params }) {
  const item = useResource(`/api/items/${encodeURIComponent(params.id)}`, { topics: ['item'] });
  const kinds = useResource('/api/kinds', { topics: ['item'] });
  const missing = absent(item);
  const data = item.data.value;
  const back = { href: href('library'), label: t('item.back') };
  // A 404 is an empty state: the item is gone, or the route is not there.
  const resources = missing ? [] : [item];
  return html`
    <${Screen} title=${data ? cleanText(data.title) || t('library.untitled') : t('item.title')} back=${back} resources=${resources}>
      ${() =>
        missing || !data
          ? html`<${Empty} text=${t('item.gone')} action=${back} />`
          : html`<${Body} item=${data} kinds=${optional(kinds) || []} />`}
    <//>`;
}

export const screen = { id: 'item', path: '/item/:id', parent: 'library', View };
