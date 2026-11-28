"""How a launcher talks to the running app.

The runtime file `<home>/run/app.json` (mode 0600, in a 0700 directory) holds
the control secret, the instance id, the pid, and the port. Only a program of
the same account can read it.

Routes (the Host check of `shell/ui/server.py` applies to each):

- `GET /health`: no cookie. `{"instance", "ok", "version"}` and no other state.
- `POST /control/open` with `Authorization: Bearer <control>`:
  `{"invite": str | null, "route": str | null}` -> `{"url": <one-time open link>}`.
- `POST /control/stop` with the bearer: `{"stopping": true}`.

A control request must have no `Origin`, no `Cookie`, and no `Sec-Fetch-Site`
header: a browser sends at least one of them on each request that a web page
makes. So a web page cannot use the control routes, also if it knew the port.

An open link (`/open/<token>`) is good for one use and `TOKEN_TTL_S` seconds.
An invite that comes through the control route is only stored as pending: the
person must confirm the join on the screen.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Body, FastAPI, Request
from fastapi.responses import JSONResponse

from anagram.admission.api import parse_invite_url, parse_lab_invite_link
from anagram.core.errors import FormatError
from anagram.core.http import bearer

HEALTH_PATH = "/health"
CONTROL_PREFIX = "/control/"
RUN_DIR = "run"
RUNTIME_FILE = "app.json"
RUNTIME_SCHEMA = "anagram.app_runtime.v1"
TOKEN_TTL_S = 60.0
MAX_TOKENS = 8
MAX_INVITE = 8192

# Control route names -> the hash of the page router.
ROUTES = {
    "join": "/#/welcome",
    "recover": "/#/welcome/recover",
    "settings": "/#/account",
    "lab-join": "/#/lab/join",
}
BROWSER_HEADERS = ("origin", "cookie", "sec-fetch-site")


# ---------------------------------------------------------------- open tokens


class OpenTokens:
    """One-time open tokens: each token works one time, for `ttl` seconds.
    At most `limit` tokens are live; a new token removes the oldest."""

    def __init__(
        self,
        ttl: float = TOKEN_TTL_S,
        limit: int = MAX_TOKENS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ttl = ttl
        self.limit = limit
        self.clock = clock
        self._lock = threading.Lock()
        self._live: dict[str, tuple[float, str]] = {}  # token -> (expiry, redirect target)

    def mint(self, route: str | None = None) -> str:
        """A new token. `route`: a name of `ROUTES`, or None for the home page."""
        if route is not None and route not in ROUTES:
            raise ValueError(f"unknown route: {route!r}")
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._expire()
            while len(self._live) >= self.limit:
                del self._live[next(iter(self._live))]
            self._live[token] = (self.clock() + self.ttl, ROUTES.get(route, "/"))
        return token

    def redeem(self, token: str) -> str | None:
        """Use a token. Return the redirect target, or None if the token is
        unknown, used, or old."""
        with self._lock:
            self._expire()
            for live in list(self._live):
                if hmac.compare_digest(live.encode(), token.encode()):
                    return self._live.pop(live)[1]
        return None

    def _expire(self) -> None:
        now = self.clock()
        for token, (expiry, _) in list(self._live.items()):
            if expiry <= now:
                del self._live[token]


# --------------------------------------------------------------- runtime file


def runtime_path(home: str | Path) -> Path:
    return Path(home) / RUN_DIR / RUNTIME_FILE


def write_runtime(home: str | Path, doc: dict) -> Path:
    """Write the runtime file atomically, mode 0600."""
    path = runtime_path(home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".app-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    return path


def read_runtime(home: str | Path) -> dict | None:
    """The runtime file, or None if it is absent or malformed."""
    try:
        doc = json.loads(runtime_path(home).read_text())
    except (FileNotFoundError, ValueError):
        return None
    ok = (
        isinstance(doc, dict)
        and doc.get("schema") == RUNTIME_SCHEMA
        and isinstance(doc.get("control"), str)
        and isinstance(doc.get("instance"), str)
        and isinstance(doc.get("port"), int)
        and isinstance(doc.get("pid"), int)
    )
    return doc if ok else None


def remove_runtime(home: str | Path, instance: str | None = None) -> None:
    """Remove the runtime file (only the file of `instance`, if given)."""
    if instance is not None:
        doc = read_runtime(home)
        if doc is not None and doc["instance"] != instance:
            return
    with contextlib.suppress(FileNotFoundError):
        os.unlink(runtime_path(home))


def runtime_doc(runtime) -> dict:
    return {
        "control": runtime.control,
        "instance": runtime.instance,
        "pid": os.getpid(),
        "port": runtime.port,
        "schema": RUNTIME_SCHEMA,
        "started_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": runtime.version,
    }


# --------------------------------------------------------------------- guard


def refuse_control(request: Request, runtime) -> JSONResponse | None:
    """The guard of a `/control/*` request (`shell/ui/server.py` calls it after the
    Host check). None: the request may go on."""
    if runtime is None or not getattr(runtime, "control", None):
        return JSONResponse({"error": "Not found."}, status_code=404)
    if any(h in request.headers for h in BROWSER_HEADERS):
        return JSONResponse({"error": "Browser requests are refused."}, status_code=403)
    given = bearer(request.headers.get("authorization")) or ""
    if not hmac.compare_digest(given.encode(), runtime.control.encode()):
        return JSONResponse({"error": "Bad control token."}, status_code=401)
    return None


# -------------------------------------------------------------------- routes


def invite_kind(url: str) -> str | None:
    """`node` or `lab` for an invite link that parses, else None."""
    try:
        parse_invite_url(url)
        return "node"
    except (FormatError, ValueError, KeyError, TypeError):
        pass
    try:
        parse_lab_invite_link(url)
        return "lab"
    except Exception:  # each fault means: not a lab invite
        return None


def accept_invite(service, url: str) -> str | None:
    """Store an invite as pending. Return the route name to open, or None
    (the invite is ignored). A node invite for a joined home is ignored."""
    kind = invite_kind(url)
    if kind is None:
        return None
    joined = service.joined()
    if kind == "node" and joined:
        return None
    if not joined:
        # The welcome screen shows this invite and joins with it (a lab
        # invite also makes the person a node member: admission.device.join.join).
        service.join.prepare(url)
    service.state.update(pending_invite={"kind": kind, "url": url})
    return "lab-join" if joined else "join"


def register(app: FastAPI, runtime) -> None:
    """Add the app routes. `runtime` is the `AppRuntime`."""

    @app.get(HEALTH_PATH)
    def health() -> dict:
        return {"instance": runtime.instance, "ok": True, "version": runtime.version}

    @app.post("/control/open")
    def control_open(body: dict = Body(default={})) -> JSONResponse:
        body = body if isinstance(body, dict) else {}
        route, invite = body.get("route"), body.get("invite")
        if route is not None and route not in ROUTES:
            return JSONResponse({"error": "Unknown route."}, status_code=400)
        if invite is not None:
            if not isinstance(invite, str) or len(invite) > MAX_INVITE:
                return JSONResponse({"error": "Bad invite."}, status_code=400)
            route = accept_invite(runtime.service, invite.strip()) or route
        token = runtime.tokens.mint(route)
        return JSONResponse({"url": f"http://127.0.0.1:{runtime.port}/open/{token}"})

    @app.post("/control/stop")
    def control_stop() -> dict:
        runtime.request_stop()
        return {"stopping": True}
