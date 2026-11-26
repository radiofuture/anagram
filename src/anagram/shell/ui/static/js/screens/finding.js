// One finding. The order of the page: the finding (its proof and its
// evidence files), then who has it, then the outputs and the versions.
// Sharing (the share sheet, "Shared with") and the outputs (certificate,
// preprint draft) come from track R5 through the slots `finding.actions`
// and `finding.sections` (js/slots/share.js, js/slots/certify.js).
import { html, useLayoutEffect, useRef } from '../core/html.js';
import { t } from '../core/copy.js';
import { fmtDate } from '../core/format.js';
import { once, takeSetDown } from '../core/motion.js';
import { useResource } from '../core/resource.js';
import { href } from '../core/router.js';
import {
  Disclosure,
  DownloadLink,
  Facts,
  Row,
  RowList,
  Screen,
  Section,
  Slot,
  TaskPanel,
} from '../components/index.js';
import { findingTitle, polarityWord, provenLine } from './library.js';

// T4: the proof panel sets down one time when the server confirms the
// timestamp: after "Make the proof" on a proposed finding, or when the proof of a waiting
// version arrives while the screen is open.
function useSetDown(ref, root, proven) {
  const was = useRef(proven);
  useLayoutEffect(() => {
    const panel = ref.current ? ref.current.closest('.ag-proof') : null;
    if (takeSetDown(root) || (proven && !was.current)) once(panel, 'ag-m-proof');
    was.current = proven;
  }, [root, proven]);
}

function Proof({ finding }) {
  const v = finding.versions[0];
  const path = `/api/findings/${encodeURIComponent(finding.root)}`;
  const ref = useRef(null);
  useSetDown(ref, finding.root, Boolean(v.proven_by));
  return html`
    <${TaskPanel} label=${t('finding.proof')}>
      <p class="ag-proof-label" ref=${ref}>${v.proven_by ? t('finding.proven_label') : t('finding.stamp_label')}</p>
      <p class="ag-proof-date" data-testid="proof-date" data-waiting=${v.proven_by ? undefined : 'true'}>
        ${v.proven_by ? fmtDate(v.proven_by) : t('library.waiting')}
      </p>
      <p class="rf-ui-help">${t('finding.check', { n: v.version })}</p>
      <div class="rf-ui-actions">
        <${Slot} name="finding.actions" props=${{ finding }} />
      </div>
      <${DownloadLink} kind="link" href=${`${path}/proof`} label=${t('finding.download')} />
    <//>`;
}

function Body({ finding }) {
  const path = `/api/findings/${encodeURIComponent(finding.root)}`;
  return html`
    ${polarityWord(finding) && html`<p class="rf-ui-help" data-testid="polarity">${polarityWord(finding)}</p>`}
    <${Proof} finding=${finding} />
    <${Section} id="evidence-title" title=${t('finding.evidence')}>
      <p class="rf-ui-help">${t('finding.evidence_help')}</p>
      <${RowList} items=${finding.evidence} keyOf=${(e) => String(e.slot)} label=${t('finding.evidence')}
        render=${(e) => html`
          <${Row} title=${e.name} meta=${e.third_party ? t('finding.third_party') : null}
            action=${
              e.on_this_computer
                ? html`<${DownloadLink} href=${`${path}/files/${e.slot}/proof`} label=${t('finding.prove')}
                  name=${t('finding.prove_name', { name: e.name })} />`
                : html`<span class="rf-ui-help ag-row-fact">${t('finding.not_here')}</span>`
            } />`} />
    <//>
    <${Slot} name="finding.sections" props=${{ finding }} />
    <${Section} id="versions-title" title=${t('finding.versions')}>
      <${RowList} ordered items=${finding.versions} keyOf=${(v) => v.root} label=${t('finding.versions')}
        render=${(v) => html`
          <${Row} title=${t('library.version', { n: v.version })} meta=${provenLine(v)} />`} />
    <//>
    <${Disclosure} kind="details" summary=${t('common.details')}>
      <${Facts} rows=${[[t('finding.id'), finding.details.finding_id], [t('finding.fingerprint'), finding.details.root]]} />
    <//>`;
}

function View({ params }) {
  const path = `/api/findings/${encodeURIComponent(params.root)}`;
  const finding = useResource(path, { topics: ['finding.changed'] });
  const f = finding.data.value;
  return html`
    <${Screen} title=${f ? findingTitle(f) : t('finding.title')} back=${{ href: href('library'), label: t('finding.back') }}
      resources=${[finding]}>
      ${() => html`<${Body} finding=${f} />`}
    <//>`;
}

export const screen = { id: 'finding', path: '/finding/:root', parent: 'library', View };
