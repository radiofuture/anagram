"""The join page of the node: `GET /join`.

An invite link is `<node_url>/join#<fragment>`. The fragment holds a node
invite or a lab invite (integration 1.5). A browser never sends the fragment
to the server, so this page is the same for each invite: it is static, and
its one script (`ui/static/node/join.js`, served at `/brand/node/join.js`)
reads `location.hash` and sets the "Open Anagram" link to
`anagram://join/<fragment>`. The operating system gives that link to the
installed app (`anagram open-url`), which shows the invite for confirmation.

"Get Anagram" links to the download page of the node config key
`download_url` (environment `ANAGRAM_DOWNLOAD_URL`). With no value, the page
has no download link.

The markup and the words are in `anagram.shell.pages`. The page sends the
node page headers (`pages.HEADERS`: CSP `script-src 'self'`, no inline
script, no referrer).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from anagram.shell import pages

SCRIPT = "/brand/node/join.js"
DOWNLOAD_ENV = "ANAGRAM_DOWNLOAD_URL"


def download_url(env: Mapping[str, str] = os.environ) -> str:
    """The download link of the node config, or "" when it is not set or is
    not an https link (http only for a loopback name, for local tests)."""
    url = (env.get(DOWNLOAD_ENV) or "").strip()
    if not url:
        return ""
    parts = urlsplit(url)
    local = parts.hostname in ("localhost", "127.0.0.1") or (parts.hostname or "").endswith(
        ".localhost"
    )
    if parts.scheme == "https" or (parts.scheme == "http" and local):
        return url
    return ""


def register(app: FastAPI, identity, *, download: str | None = None) -> None:
    """Add `GET /join`. `identity` gives the community name; `download` is
    the download link (None: read `ANAGRAM_DOWNLOAD_URL` now)."""
    get = download_url() if download is None else download

    @app.get("/join", response_class=HTMLResponse)
    def join_page() -> HTMLResponse:
        body = pages.join(identity.cfg.community, download_url=get, script=SCRIPT)
        return HTMLResponse(body, headers=pages.HEADERS)
