"""MCP over loopback HTTP (stdio and loopback only, no public URL).

For a local agent that cannot start a process (for example a lab's own
agent service on this computer). The Streamable HTTP transport of MCP,
in its JSON form: one JSON-RPC message in the body of `POST /mcp`, one JSON
answer (or 202 with no body for a notification). No event stream, no
session id.

The checks of `local-ui-boundary` for a route that a browser must not use
(as the control route of the app):

- Bind to `127.0.0.1` only.
- The `Host` header must be this loopback address and port (DNS
  rebinding).
- A request with an `Origin`, `Cookie`, `Sec-Fetch-Site` or
  `Sec-Fetch-Mode` header is refused: a browser always sends one of them.
- No CORS header in any answer. `OPTIONS` gets 405.
- `Authorization: Bearer <key>`: the key of one grant (`access.new_http_key`;
  the record keeps its SHA-256). It is read again at each request, so a
  revoke or a new key has effect at once.
- No access log; the log has no path, query, or body.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer

from anagram.gateway import access
from anagram.gateway.server import Policy, Server, Session

log = logging.getLogger("anagram.gateway")

LOOPBACK = "127.0.0.1"
PATH = "/mcp"
MAX_BODY = 1_000_000
DEFAULT_PORT = 47830
BROWSER_HEADERS = ("Origin", "Cookie", "Sec-Fetch-Site", "Sec-Fetch-Mode")


def resolve_grant(open_session: Session, key: str) -> str | None:
    with open_session() as (_, index):
        grant = access.find_by_key(index, key)
    return None if grant is None else grant.id


class Gateway(HTTPServer):
    """The loopback HTTP server. `port` 0 takes a free port (`self.port`)."""

    def __init__(
        self,
        open_session: Session,
        *,
        policy: Policy,
        port: int = DEFAULT_PORT,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.open_session = open_session
        self.policy = policy
        self.clock = clock
        super().__init__((LOOPBACK, port), _Handler)
        self.port = self.server_address[1]
        self.hosts = {f"{LOOPBACK}:{self.port}", f"localhost:{self.port}"}

    def url(self) -> str:
        return f"http://{LOOPBACK}:{self.port}{PATH}"

    def server_for(self, grant_id: str) -> Server:
        kw = {} if self.clock is None else {"clock": self.clock}
        return Server(self.open_session, grant_id, policy=self.policy, **kw)


class _Handler(BaseHTTPRequestHandler):
    server: Gateway
    server_version = "anagram"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # no access log (local-ui-boundary)

    def _send(self, status: int, body: dict | None = None, extra: dict | None = None) -> None:
        data = b"" if body is None else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _refuse(self, status: int, message: str, extra: dict | None = None) -> None:
        # The body of a refused request may be unread: end the connection.
        self.close_connection = True
        self._send(status, {"error": message}, {**(extra or {}), "Connection": "close"})

    def _guard(self) -> bool:
        if self.headers.get("Host", "") not in self.server.hosts:
            self._refuse(421, "wrong host")
            return False
        if any(self.headers.get(h) is not None for h in BROWSER_HEADERS):
            self._refuse(403, "a browser cannot use this route")
            return False
        if self.path.split("?", 1)[0] != PATH:
            self._refuse(404, "not found")
            return False
        return True

    def _not_allowed(self) -> None:
        if self._guard():
            self._refuse(405, "use POST", {"Allow": "POST"})

    do_GET = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _not_allowed  # noqa: N815

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard():
            return
        auth = self.headers.get("Authorization", "")
        scheme, _, key = auth.partition(" ")
        grant_id = (
            resolve_grant(self.server.open_session, key.strip()) if scheme == "Bearer" else None
        )
        if grant_id is None:
            self._refuse(401, "give the key of the setup text", {"WWW-Authenticate": "Bearer"})
            return
        if "application/json" not in self.headers.get("Content-Type", ""):
            self._refuse(415, "send JSON")
            return
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._refuse(411, "give the length")
            return
        if not 0 < size <= MAX_BODY:
            self._refuse(413, "too large")
            return
        raw = self.rfile.read(size)
        try:
            message = json.loads(raw)
        except ValueError:
            self._send(400, {"error": {"code": -32700, "message": "Parse error"}, "id": None,
                             "jsonrpc": "2.0"})  # fmt: skip
            return
        try:
            answer = self.server.server_for(grant_id).handle(message)
        except Exception:  # the log gets the class only
            log.error("http request failed", exc_info=False)
            self._refuse(500, "Anagram could not answer now")
            return
        if answer is None:
            self._send(202)
        else:
            self._send(200, answer)
