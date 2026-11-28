// Slot view `account.sections`: "This computer".
// The start at login switch, the state of the helper (live from `app.helper`
// events), where the keys are, and the version. Routes: `GET /api/app`,
// `PUT /api/app/start-at-login`, `POST /api/app/restart-helper`. Words:
// `copy/computer.json`. No path shows.
import { html, useState } from '../core/html.js';
import { has, t } from '../core/copy.js';
import { provide } from '../core/slots.js';
import { fmtTime } from '../core/format.js';
import { mutate, optional, useResource } from '../core/resource.js';
import { ActionButton, ErrorLine, Facts, Section, Switch } from '../components/index.js';

const word = (key, fallback) => (has(key) ? t(key) : fallback);

function helperText(helper) {
  const state = word(`computer.helper_${helper.state}`, helper.state);
  return helper.state === 'running' && helper.last_cycle_at
    ? t('computer.helper_checked', { state, time: fmtTime(helper.last_cycle_at) })
    : state;
}

function StartAtLogin({ block }) {
  const [on, setOn] = useState(block.on);
  const [error, setError] = useState('');
  if (block.manager === 'none') return html`<p class="rf-ui-help">${t('computer.login_none')}</p>`;
  const change = async (value) => {
    setOn(value);
    setError('');
    try {
      const out = await mutate('PUT', '/api/app/start-at-login', { on: value }, { invalidate: ['/api/app'] });
      setOn(out.on);
    } catch (err) {
      setOn(!value);
      setError(err.message);
    }
  };
  return html`
    <${Switch} id="start-at-login" label=${t('computer.login')} checked=${on} onChange=${change} />
    <p class="rf-ui-help ag-computer-help">${t('computer.login_help')}</p>
    <${ErrorLine} text=${error} />`;
}

function ThisComputer() {
  const app = useResource('/api/app', { topics: ['app'] });
  const [error, setError] = useState('');
  const data = optional(app);
  if (!data) return null;
  const { helper, keys, start_at_login: login, update, version } = data;
  const restart = () => mutate('POST', '/api/app/restart-helper', {}, { invalidate: ['/api/app'] });
  return html`
    <${Section} id="computer-title" title=${t('computer.title')}>
      <${StartAtLogin} key=${String(login.on)} block=${login} />
      <${Facts} rows=${[
        [t('computer.helper'), helperText(helper)],
        // Keys in files: note it once here.
        [
          t('computer.keys'),
          keys.protected
            ? word(`computer.keys_${keys.backend.replace(/-/g, '_')}`, t('computer.keys_other'))
            : t('computer.keys_files'),
        ],
        [t('computer.version'), version],
        [
          t('computer.update'),
          update.available && update.version ? t('computer.update_ready', { version: update.version }) : null,
        ],
      ]} />
      ${update.available && update.url && html`<p><a href=${update.url} target="_blank" rel="noopener noreferrer">${t('computer.update_get')}</a></p>`}
      ${
        helper.state === 'error' &&
        html`
        <${ErrorLine} text=${error} />
        <div class="rf-ui-actions">
          <${ActionButton} kind="secondary" label=${t('computer.restart')} busyLabel=${t('computer.restarting')}
            run=${restart} errorTo=${setError} />
        </div>`
      }
    <//>`;
}

provide('account.sections', { order: 10, View: ThisComputer });
