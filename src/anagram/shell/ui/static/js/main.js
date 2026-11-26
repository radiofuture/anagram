// Boot of the local UI. The page finds its screens, slot modules, styles, and
// copy by directory (GET /api/ui/manifest, GET /api/ui/copy), so a track adds
// a file and edits no shared file.
import { html, render } from './core/html.js';
import { api, hooks } from './core/api.js';
import { setCopy, t } from './core/copy.js';
import { store } from './core/store.js';
import { resource, setStreamCheck } from './core/resource.js';
import { connect, ready } from './core/events.js';
import { register, start } from './core/router.js';
import { Shell } from './components/Shell.js';

const overview = resource('/api/overview', { topics: ['overview.changed'], data: store.overview });
overview.users = 1; // the shell always reads it

// The product cannot start. A locked keychain is a state the person can
// correct (423 with `keychain`): it has its own words and no error colour.
function Fault() {
  const locked = Boolean(store.fault.value?.keychain);
  return html`
    <main id="main" class="ag-alone" tabindex="-1" data-screen=${locked ? 'locked' : 'fault'} data-state="error">
      <h1 class="ag-title">${t(locked ? 'common.locked_title' : 'common.fault_title')}</h1>
      ${
        locked
          ? html`<p class="ag-lead" role="alert">${t('common.locked_text')}</p>`
          : html`<p class="rf-ui-error" role="alert">${store.fault.value}</p>`
      }
      <div class="rf-ui-actions">
        <button type="button" class="rf-ui-button" onClick=${() => window.location.reload()}>${t('common.try_again')}</button>
      </div>
    </main>`;
}

let Launch = null;

function Root() {
  if (store.launch.value && Launch)
    return html`<main id="main" class="ag-alone" tabindex="-1" data-screen="launch" data-state="ready"><${Launch} /></main>`;
  if (store.fault.value) return html`<${Fault} />`;
  if (!store.overview.value) return null;
  return html`<${Shell} />`;
}

// The words for a page that the server refuses: static files need no cookie.
async function staticCopy() {
  const out = {};
  await Promise.all(
    ['common', 'launch'].map(async (name) => {
      try {
        const res = await fetch(`/static/copy/${name}.json`, { credentials: 'same-origin' });
        if (res.ok) out[name] = await res.json();
      } catch {
        // The page then shows the keys.
      }
    }),
  );
  setCopy(out);
}

async function showLaunch() {
  if (store.launch.peek()) return;
  if (!Launch) {
    await staticCopy();
    Launch = (await import('./screens/launch.js')).screen.View;
  }
  store.launch.value = true;
}

function addStyles(names) {
  for (const name of names) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = `/static/css/screens/${name}`;
    document.head.append(link);
  }
}

async function boot() {
  hooks.launch = showLaunch;
  hooks.signin = () => overview.reload();
  render(html`<${Root} />`, document.getElementById('app'));
  let manifest;
  try {
    const [found, copy] = await Promise.all([api('GET', '/api/ui/manifest'), api('GET', '/api/ui/copy')]);
    manifest = found;
    setCopy(copy);
  } catch (err) {
    if (err.status === 401) return; // hooks.launch shows the launch screen
    await staticCopy();
    store.fault.value = err.message;
    return;
  }
  addStyles(manifest.styles || []);
  const modules = await Promise.all([
    ...(manifest.screens || []).map((name) => import(`./screens/${name}`)),
    ...(manifest.slots || []).map((name) => import(`./slots/${name}`)),
  ]);
  for (const mod of modules) if (mod.screen && mod.screen.path !== undefined) register(mod.screen);
  setStreamCheck(() => store.conn.value === 'live');
  // The stream first: no event is lost between a load and the stream.
  connect();
  await ready();
  await overview.load();
  const err = overview.error.value;
  if (err && !store.launch.peek()) {
    store.fault.value = err.status === 423 && err.data && err.data.keychain ? { keychain: true } : err.message;
    return;
  }
  start();
}

boot();
