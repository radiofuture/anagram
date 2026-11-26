# Local UI boundary

A design pattern of Anagram (`anagram.shell.ui.server`). Use it when a
product runs a web UI on the person's own computer and that UI touches keys
or plaintext. A remote server never serves this UI.

Rules:

- Bind to `127.0.0.1` only. Use a free port.
- Make a new secret token for each launch. Put it only in the URL that the
  command prints or opens (`/open/<token>`). Exchange it for an HttpOnly,
  SameSite=Strict cookie. Put the port in the cookie name, so that two local
  UIs on one computer do not share a cookie.
- On every request, check the Host header against this loopback address and
  port (DNS rebinding). If an Origin header is present, it must be this
  origin. A request that changes state must have this Origin (CSRF). Refuse
  `Sec-Fetch-Site: cross-site`.
- Send no CORS headers. Send a strict Content Security Policy (this origin
  only; no frames), `Referrer-Policy: no-referrer`, and `no-store` for data.
- An external sign-in returns to one callback route. That route needs no
  cookie, accepts only the one flow that this UI started, and changes
  nothing else.
- Static files ship in the package: no build step and no CDN. Put text into
  the page as text, never as HTML.
- Vendored JavaScript modules have a manifest with the version, the source
  and the SHA-256 of each file. A test compares the files with the manifest.
  Only the import map is inline, and the CSP has its hash.
- An event stream route (Server-Sent Events) goes through the same guard and
  cookie as each API route. Do not use a WebSocket: the browser does not
  apply the same-origin rules to it.
- Keep one "What leaves this computer" list as data in the code
  (`anagram.shell.ui.flows`), and show it.

When the UI runs as a login service:

- A launcher gets a one-time open link through a control route
  (`/control/open`). The control secret is in a runtime file with mode 0600.
  A one-time open token works one time, for 60 seconds, and at most 8 are
  live.
- The control route refuses each request that has an `Origin`, `Cookie` or
  `Sec-Fetch-Site` header (a browser always sends one of them), and compares
  the bearer in constant time. It sets no cookie.
- A health route gives no state: an instance ID and the version only.
- A URL scheme (`anagram://`) carries only data that the UI shows for
  confirmation, for example a pending invite. It never starts an action.
- The service log has no access log, and it removes paths, URL queries and
  exception text.

Tests: `tests/test_ui_api.py`, `tests/test_app_control.py` and
`tests/test_open_url.py`.
