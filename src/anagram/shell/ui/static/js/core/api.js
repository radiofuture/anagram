// The JSON API of the local server.
import { t } from './copy.js';

export class ApiError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data || {};
  }
}

// main.js sets these: the server refused the cookie (`launch`), or the node
// ended the session (`signin`).
export const hooks = { launch: null, signin: null };

export async function api(method, path, body, { signal } = {}) {
  const init = { method, headers: { Accept: 'application/json' }, credentials: 'same-origin', signal };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError(0, t('common.no_answer'));
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    if (data?.launch && hooks.launch) hooks.launch();
    if (data?.signin && hooks.signin) hooks.signin();
    // The status code is for the log, not for the person.
    if (!data?.error) console.warn(`api: ${method} ${path} gave ${res.status}`);
    throw new ApiError(res.status, data?.error || t('common.failed'), data);
  }
  return data;
}

/** A GET for a search field. A newer search stops it with `signal`. */
export function search(path, signal) {
  return api('GET', path, undefined, { signal });
}
