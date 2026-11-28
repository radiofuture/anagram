# Live local UI

A design pattern of Anagram (`anagram.shell.ui`). Use it with the
[local UI boundary](local-ui-boundary.md) when the local UI must show state
that changes while the page is open (progress, new items, the state of a
sign-in).

Render:

- Keyed components from vendored ES modules (Preact, htm, signals), with no
  build step. One module (`src/anagram/shell/ui/static/js/core/html.js`)
  imports the vendored files. The import map is the one inline script; the
  CSP has its hash.
- No style attributes (the CSP has no `unsafe-inline` for styles): a
  component sets a value with `style.setProperty` in a ref.
- All visible text comes from copy files
  (`src/anagram/shell/ui/static/copy/<screen>.json`) through
  `t('screen.key', params)`. A lint test finds literal text, unused keys and
  missing keys.

Live state:

- One event stream for each page: `GET /api/events` (Server-Sent Events)
  with replay from `Last-Event-ID`, a `hello` frame with a server ID, and
  `resync` when replay is not possible. A new server ID makes the page load
  its data again.
- A resource is a cached GET with stale-while-revalidate. It names the event
  topics that make it stale. A change through the UI names the resources
  that it changes.
- Work in another thread or process writes rows to a table; a bridge thread
  reads the rows only while a page is open, and publishes them.
- Events carry IDs and counts, never file paths or content.

Screens:

- A screen module exports `{id, path, nav, parent, View}`. The server lists
  the modules by directory (`GET /api/ui/manifest`), so a new screen is one
  file and one copy file.
- The router keeps the scroll position and the focus for Back, moves focus
  to the title on a forward change, and sets
  `main[data-screen][data-state]` so that tests wait for a state, not on
  time.

Motion: the brand timings only, nothing loops, and reduced motion changes at
once.

Tests: `tests/test_ui_events.py`, `tests/test_ui_browser.py`,
`tests/test_ui_visual.py` and `tests/test_ui_copy.py`.
