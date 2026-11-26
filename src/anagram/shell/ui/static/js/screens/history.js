// What you shared with one person (`#/sharing/with/:subject`): each finding,
// its state, and the record of each share. Track R5 owns this screen.
import { html } from '../core/html.js';
import { t } from '../core/copy.js';
import { useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import { Disclosure, DownloadLink, Empty, Row, RowList, Screen } from '../components/index.js';
import { StateLine, personName } from '../parts/shares.js';

const LIMITS = [
  'sharing.about_opened',
  'sharing.about_copy',
  'sharing.about_changed',
  'sharing.about_node',
  'sharing.about_public',
];

function Shared({ row, subject }) {
  const record = `/api/history/${encodeURIComponent(row.finding.id)}/${encodeURIComponent(subject)}/record`;
  return html`
    <${Row} title=${row.finding.title} href=${href('finding', { root: row.finding.root })}
      meta=${html`<${StateLine} row=${row} />`}
      action=${html`<${DownloadLink} kind="link" href=${record} label=${t('sharing.export')}
        name=${t('sharing.export_name', { title: row.finding.title })} />`} />`;
}

function View({ params }) {
  const path = `/api/history?person=${encodeURIComponent(params.subject)}`;
  const history = useResource(path, { topics: ['share', 'finding.changed'] });
  const rows = history.data.value;
  const name = rows?.length ? personName(rows[0]) : t('sharing.a_member');
  return html`
    <${Screen} title=${rows ? name : t('sharing.title')} resources=${[history]}
      back=${{ href: href('sharing', { tab: 'by-me' }), label: t('sharing.tab_by_me') }}>
      ${() => html`
        <${RowList} items=${rows} keyOf=${(r) => r.finding.id} label=${t('sharing.person_list', { name })}
          render=${(r) => html`<${Shared} row=${r} subject=${params.subject} />`}
          empty=${html`<${Empty} text=${t('sharing.person_empty')} />`} />
        <${Disclosure} summary=${t('sharing.about_record')}>
          <ul class="ag-share-limits">${LIMITS.map((k) => html`<li key=${k}>${t(k)}</li>`)}</ul>
        <//>`}
    <//>`;
}

export const screen = { id: 'history', path: '/sharing/with/:subject', parent: 'sharing', View };
