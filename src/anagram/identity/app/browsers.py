"""Browsers for the ORCID step of a sign-in (layer L1): the system browser
with a loopback port, a pasted one-time code, and a headless browser for the
fake ORCID of local development and tests. Also the PKCE pair of the flow."""

from __future__ import annotations

import hashlib
import http.server
import secrets
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable

from anagram.core.errors import ClientError
from anagram.core.signed import b64url


class Browser:
    """Runs the ORCID step. `return_to` is where the node sends the one-time code.
    `open(url)` returns the callback parameters (`code`, and `state` if present)."""

    return_to: str = "urn:anagram:oob"

    def open(self, url: str) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class LoopbackBrowser(Browser):  # pragma: no cover - opens a real browser
    """Opens the system browser and waits on a loopback port for the node's
    redirect. ORCID itself only ever redirects to the node, never here."""

    def __init__(self, timeout: float = 300) -> None:
        self.timeout = timeout
        self.result: dict = {}
        done = threading.Event()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                outer.result = {k: v[0] for k, v in q.items()}
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<p>Signed in. You can close this window.</p>")
                done.set()

            def log_message(self, *args):
                pass

        self._done = done
        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.return_to = f"http://127.0.0.1:{self._server.server_port}/callback"

    def open(self, url: str) -> dict:
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()
        print(f"Opening your browser for sign-in. If it does not open, visit:\n  {url}")
        webbrowser.open(url)
        ok = self._done.wait(self.timeout)
        self._server.shutdown()
        if not ok:
            raise ClientError("sign-in timed out")
        return self.result


class PasteBrowser(Browser):  # pragma: no cover - interactive
    """No local port: the node shows the one-time code and the user pastes it."""

    def open(self, url: str) -> dict:
        print(f"Open this URL, sign in, then paste the one-time code here:\n  {url}")
        return {"code": input("One-time code: ").strip()}


# fetch(url) -> (status, Location header or None)
Fetch = Callable[[str], tuple[int, str | None]]


class HeadlessBrowser(Browser):
    """Follows redirects with no user step. Works only with the node's fake ORCID
    (local development and tests)."""

    return_to = "http://127.0.0.1:9/callback"  # never contacted

    def __init__(self, fetch: Fetch, max_hops: int = 5) -> None:
        self.fetch = fetch
        self.max_hops = max_hops

    def open(self, url: str) -> dict:
        for _ in range(self.max_hops):
            if url.startswith(self.return_to):
                q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                return {k: v[0] for k, v in q.items()}
            status, location = self.fetch(url)
            if status not in (301, 302, 303, 307, 308) or not location:
                raise ClientError(f"sign-in stopped at {url} (status {status})")
            url = urllib.parse.urljoin(url, location)
        raise ClientError("too many redirects during sign-in")


def urllib_fetch(url: str) -> tuple[int, str | None]:  # pragma: no cover - network
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    if not url.startswith(("http://", "https://")):
        raise ClientError("bad URL")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(url, timeout=30) as resp:
            return resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location")


def pkce() -> tuple[str, str]:
    """A PKCE verifier and its challenge (base64url SHA-256)."""
    verifier = secrets.token_urlsafe(48)
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge
