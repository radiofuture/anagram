// Join a lab (`#/lab/join`). The app opens this screen
// for an `anagram://` lab link (control route "lab-join"): the link is the
// pending invite of the app, and `GET /api/labs/invite` shows what it is.
// With no pending link, the person pastes the link. The join is one click;
// then the lab screen opens.
import { html, useState } from '../core/html.js';
import { t } from '../core/copy.js';
import { announce } from '../core/a11y.js';
import { fmtDate } from '../core/format.js';
import { mutate, useResource } from '../core/resource.js';
import { api } from '../core/api.js';
import { href, navigate } from '../core/router.js';
import {
  ActionButton,
  Button,
  Empty,
  ErrorLine,
  Facts,
  Field,
  Screen,
  TaskPanel,
  TextArea,
} from '../components/index.js';

const roleName = (role) => t(`lab.role_${role}`);

function Preview({ invite, url, again }) {
  const [error, setError] = useState('');
  const join = async () => {
    const out = await mutate('POST', '/api/labs/join', url ? { url } : {}, { invalidate: ['/api/labs/mine'] });
    if (out.signin) {
      navigate(href('welcome'));
      return;
    }
    announce(t('labjoin.joined', { lab: out.name }));
    navigate(href('lab', { id: out.id }), { replace: true });
  };
  if (invite.member) {
    return html`<${Empty} text=${t('labjoin.member', { lab: invite.lab })}
      action=${{ href: href('lab', { id: invite.id }), label: t('labjoin.open_lab', { lab: invite.lab }) }} />`;
  }
  if (!invite.open) {
    return html`
      <${Empty} text=${t('labjoin.closed', { lab: invite.lab })} />
      <${Button} kind="quiet" onClick=${again}>${t('labjoin.other_link')}<//>`;
  }
  return html`
    <${TaskPanel} label=${t('labjoin.panel', { lab: invite.lab })}>
      <p class="ag-proof-label">${t('labjoin.invited')}</p>
      <h2 class="ag-panel-title">${invite.lab}</h2>
      <${Facts} rows=${[
        [t('labjoin.role'), roleName(invite.role)],
        [t('labjoin.by'), invite.by],
        [t('labjoin.host'), invite.host],
        [t('labjoin.until'), fmtDate(invite.expires_at)],
      ]} />
      <p class="rf-ui-help">${t('labjoin.reads')}</p>
      <${ErrorLine} text=${error} />
      <div class="rf-ui-actions">
        <${ActionButton} label=${t('labjoin.join', { lab: invite.lab })} busyLabel=${t('labjoin.joining')} run=${join}
          errorTo=${setError} />
      </div>
    <//>`;
}

function Paste({ onPreview }) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const look = async () => {
    const link = url.trim();
    if (!link) throw new Error(t('labjoin.paste_empty'));
    const invite = await api('GET', `/api/labs/invite?url=${encodeURIComponent(link)}`);
    onPreview({ invite, url: link });
  };
  return html`
    <${Field} id="lab-link" label=${t('labjoin.paste')} help=${t('labjoin.paste_help')}>
      <${TextArea} value=${url} onInput=${setUrl} rows="3" spellcheck=${false} autocomplete="off" />
    <//>
    <${ErrorLine} text=${error} />
    <div class="rf-ui-actions">
      <${ActionButton} label=${t('labjoin.look')} busyLabel=${t('labjoin.looking')} run=${look} errorTo=${setError} />
    </div>`;
}

function View() {
  const pending = useResource('/api/labs/invite');
  const [pasted, setPasted] = useState(null);
  const [ignore, setIgnore] = useState(false);
  // No pending link (404), or a pending link that is not a lab link: paste one.
  const none = Boolean(pending.error.value) || ignore;
  const shown = pasted || (!none && pending.data.value ? { invite: pending.data.value, url: null } : null);
  const again = () => {
    setPasted(null);
    setIgnore(true);
  };
  return html`
    <${Screen} title=${t('labjoin.title')} resources=${none || pasted ? [] : [pending]}>
      ${() =>
        shown
          ? html`<${Preview} invite=${shown.invite} url=${shown.url} again=${again} />`
          : html`<${Paste} onPreview=${setPasted} />`}
    <//>`;
}

export const screen = { id: 'labjoin', path: '/lab/join', parent: 'lab', View };
