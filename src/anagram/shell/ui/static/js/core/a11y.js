// The one live region for announcements, and focus on the screen title.

let lastAt = 0;

/**
 * Say a text in the status region (#announce in index.html).
 * `gap`: the least time in ms after the announcement before; a text that
 * comes too soon is not said (live rows, at most one each 5 s).
 */
export function announce(text, { gap = 0 } = {}) {
  const region = document.getElementById('announce');
  if (!region || !text) return false;
  const now = Date.now();
  if (gap && now - lastAt < gap) return false;
  lastAt = now;
  region.textContent = '';
  requestAnimationFrame(() => {
    region.textContent = text;
  });
  return true;
}

/** Put focus on the title of the screen, or on the work area. */
export function focusTitle() {
  const main = document.getElementById('main');
  if (!main) return;
  const title = main.querySelector('h1');
  (title || main).focus({ preventScroll: true });
}
