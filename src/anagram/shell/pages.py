"""Server-rendered pages in the brand.

One module makes each HTML page that a server renders: the organizer page
(`/admin`), the join page of the node (`/join`), the ORCID callback
pages, the fake ORCID page, and the two small pages of the local UI server
(`/open/<token>` refused, `/auth/callback`).

Rules:

- The caller escapes all values with `html.escape` before it gives `body`.
  `page` and `notice` escape the title, the text, and the action themselves.
- No inline style and no inline script. The styles are the unchanged brand
  copy (`ui/static/brand`) and `ui/static/css/node.css`. A page has a script
  only if it needs one (the passkey on `/admin`, the fragment on `/join`).
- No external reference: fonts and styles come from this server.

This module imports no layer and not `anagram.shell.ui`.
"""

from __future__ import annotations

import html
from pathlib import Path

_HERE = Path(__file__).resolve().parent
BRAND_DIR = _HERE / "ui" / "static" / "brand"
NODE_CSS = _HERE / "ui" / "static" / "css" / "node.css"
NODE_DIR = _HERE / "ui" / "static" / "node"

#: The headers of a node page. The local UI server has its own CSP.
CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'; "
    "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)
HEADERS = {
    "Content-Security-Policy": CSP,
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
#: The fake ORCID form ends on the loopback callback of the local UI after two
#: redirects, and a browser applies `form-action` to each redirect.
FAKE_ORCID_HEADERS = HEADERS | {
    "Content-Security-Policy": CSP.replace(
        "form-action 'self'", "form-action 'self' http://127.0.0.1:* http://localhost:*"
    )
}

# The four frames of the brand mark (brand/assets/four-squares.svg), inline so
# that it takes the text color in the two appearances.
_MARK = (
    '<svg class="ag-node-mark" viewBox="0 0 1232 90" aria-hidden="true" focusable="false">'
    '<path d="M7 90V7H225V90 M263 0V83H481V0 M519 90V7H969V90 M1007 90V7H1225V90" '
    'fill="none" stroke="currentColor" stroke-width="14" stroke-linejoin="miter"/></svg>'
)

#: The words of the node pages. One place, so that a copy review
#: and the lint in tests/test_pages.py see all of them.
WORDS = {
    "product": "Anagram",
    "join_title": "Join {community} on Anagram",
    "join_open": "Open Anagram",
    "join_get": "Get Anagram",
    "join_promise": "This server does not get your keys or your files.",
    "join_fallback": "Anagram does not open",
    "join_fallback_text": "Copy this link and paste it in Anagram.",
    "join_link_label": "Invite link",
    "open_old_title": "This link is old",
    "open_old_text": "An open link works one time.",
    "open_action": "Open Anagram",
    "signed_in_title": "Signed in",
    "signed_in_text": "Anagram opens now.",
    "signin_old_title": "This sign-in is old",
    "signin_old_text": "Start the sign-in again in Anagram.",
    "continue": "Continue",
    "finish_title": "Finish sign-in",
    "finish_text": "Copy this code and paste it in Anagram. You can use it one time.",
    "finish_label": "One-time code",
    "fake_title": "Sign in",
    "fake_note": "Test sign-in. Not ORCID.",
    "fake_orcid": "ORCID iD",
    "fake_name": "Name",
    "fake_action": "Sign in",
}


def page(
    title: str,
    body: str,
    *,
    base: str = "/brand",
    script: str | None = None,
    node_css: str | None = None,
    refresh: str | None = None,
    wide: bool = False,
) -> str:
    """A full HTML document in the brand: tokens, font, lavender field, one
    reading column, the wordmark, and `body` (already escaped by the caller).

    `base` is the URL of the brand copy (`/brand` on the node, `/static/brand`
    in the local UI). `node_css` is the URL of node.css (default
    `<base>/node.css`). `refresh` is a same-origin URL to go to at once.
    `wide` gives the column of the organizer page."""
    esc = html.escape
    css = node_css or f"{base}/node.css"
    links = "".join(
        f'<link rel="stylesheet" href="{esc(href)}">'
        for href in (
            f"{base}/tokens.css",
            f"{base}/product-ui/tokens.css",
            f"{base}/product-ui/components.css",
            css,
        )
    )
    meta = f'<meta http-equiv="refresh" content="0; url={esc(refresh)}">' if refresh else ""
    tail = f'<script src="{esc(script)}" defer></script>' if script else ""
    column = "ag-node ag-node--wide" if wide else "ag-node"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        f"<title>{esc(title)}</title>"
        f'<link rel="icon" href="{esc(base)}/assets/four-squares.svg" type="image/svg+xml">'
        f"{links}{meta}{tail}</head>"
        f'<body class="rf-ui"><div class="{column}">'
        f'<header class="ag-node-brand">{_MARK}'
        f'<span class="ag-node-name">{esc(WORDS["product"])}</span></header>'
        f'<main class="ag-node-main">{body}</main></div></body></html>'
    )


def notice(
    title: str,
    text: str,
    *,
    action: tuple[str, str] | None = None,
    extra: str = "",
    **kw,
) -> str:
    """A page with one title, one sentence, and at most one link (label, href).
    `extra` is escaped HTML that goes after the sentence (for example a code)."""
    esc = html.escape
    link = ""
    if action is not None:
        label, href = action
        link = (
            f'<p class="ag-node-actions"><a class="rf-ui-button" href="{esc(href)}">'
            f"{esc(label)}</a></p>"
        )
    body = f'<h1 class="ag-node-title">{esc(title)}</h1><p>{esc(text)}</p>{extra}{link}'
    return page(title, body, **kw)


def code_notice(title: str, text: str, label: str, code: str, **kw) -> str:
    """A notice with one value to copy (no script: the value selects with one click)."""
    esc = html.escape
    extra = (
        f'<div class="ag-node-code"><p class="ag-node-label">{esc(label)}</p>'
        f"<pre>{esc(code)}</pre></div>"
    )
    return notice(title, text, extra=extra, **kw)


def orcid_code(one_time: str) -> str:
    """The node page after an ORCID sign-in with no loopback return (the CLI path)."""
    return code_notice(WORDS["finish_title"], WORDS["finish_text"], WORDS["finish_label"], one_time)


def fake_orcid(state: str, redirect_uri: str) -> str:
    """The sign-in form of the fake ORCID (local development and tests only)."""
    esc = html.escape
    w = WORDS
    body = (
        f'<h1 class="ag-node-title">{esc(w["fake_title"])}</h1>'
        f'<p class="ag-node-warn">{esc(w["fake_note"])}</p>'
        '<form class="ag-node-form" method="get">'
        f'<input type="hidden" name="state" value="{esc(state)}">'
        f'<input type="hidden" name="redirect_uri" value="{esc(redirect_uri)}">'
        f'<p class="rf-ui-field"><label for="orcid">{esc(w["fake_orcid"])}</label>'
        '<input class="rf-ui-input" id="orcid" name="orcid" value="fake-" autocomplete="off"></p>'
        f'<p class="rf-ui-field"><label for="name">{esc(w["fake_name"])}</label>'
        '<input class="rf-ui-input" id="name" name="name" autocomplete="off"></p>'
        f'<p class="ag-node-actions"><button class="rf-ui-button">{esc(w["fake_action"])}</button></p>'
        "</form>"
    )
    return page(w["fake_title"], body)


def join(community: str, *, download_url: str = "", script: str | None = None) -> str:
    """The join page of the node (`/join`). `shell/node/join_page.py` owns the route and the script.

    Without the script, "Open Anagram" opens the app with no invite. The
    script (`/brand/node/join.js`) reads `location.hash`, sets the link of
    `#join-open` to `anagram://join/<fragment>`, and shows `#join-link` with the
    full link. The fragment never goes to the server."""
    esc = html.escape
    w = WORDS
    title = w["join_title"].format(community=community)
    get = (
        f'<a class="rf-ui-button rf-ui-button--secondary" href="{esc(download_url)}">'
        f"{esc(w['join_get'])}</a>"
        if download_url
        else ""
    )
    body = (
        f'<h1 class="ag-node-title">{esc(title)}</h1>'
        f"<p>{esc(w['join_promise'])}</p>"
        '<p class="ag-node-actions">'
        f'<a class="rf-ui-button" id="join-open" href="anagram://open">{esc(w["join_open"])}</a>'
        f"{get}</p>"
        f'<details class="ag-node-more"><summary>{esc(w["join_fallback"])}</summary>'
        f"<p>{esc(w['join_fallback_text'])}</p>"
        f'<p class="rf-ui-field" id="join-link-field" hidden><label for="join-link">'
        f"{esc(w['join_link_label'])}</label>"
        '<input class="rf-ui-input" id="join-link" readonly spellcheck="false"></p>'
        "</details>"
    )
    return page(title, body, script=script)
