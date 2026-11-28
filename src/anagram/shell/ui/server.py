"""The local web UI server (FastAPI on 127.0.0.1).

`anagram` with no arguments (or `anagram ui`) starts it and opens the browser.
The community node never serves this UI. Only this local server touches keys
and plaintext.

Security (each request):

- Bind to 127.0.0.1 only. A random free port by default.
- A new secret token for each launch, in the opened URL (`/open/<token>`). The
  server exchanges it for an HttpOnly, SameSite=Strict cookie. The cookie name
  has the port, so two local UIs do not mix their cookies.
- Every request: the Host header must be this loopback address and port (DNS
  rebinding defense). If an Origin header is present, it must be this origin.
  A request that changes state must have this Origin (CSRF defense). A
  cross-site fetch (`Sec-Fetch-Site: cross-site`) is refused.
- No CORS headers. A strict Content Security Policy: only this origin's
  scripts and styles; no frames.
- `/auth/callback` is the only route that a cross-site page can reach: an
  ORCID sign-in or an ORCID link at the node ends there (optional). It
  needs no cookie, and it accepts only the
  one sign-in flow that this UI started.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import socket
import threading
import time
import webbrowser
from importlib import resources
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles

from anagram.shell import pages
from anagram.shell.app.control import CONTROL_PREFIX, OpenTokens, refuse_control
from anagram.shell.ui.bridge import Live
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.events import EventBus
from anagram.shell.ui.routers import UIContext, register_all
from anagram.shell.ui.service import UIService
from anagram.shell.ui.tasks import TaskRunner

STATIC = Path(str(resources.files("anagram.shell.ui").joinpath("static")))


def importmap_hash(html: str) -> str:
    """The CSP hash of the import map in the shell: the one inline block that
    the page can have. The map names the vendored modules (static/vendor)."""
    found = re.search(r'<script type="importmap">(.*?)</script>', html, re.DOTALL)
    if found is None:
        raise RuntimeError("the shell has no import map")
    return base64.b64encode(hashlib.sha256(found.group(1).encode()).digest()).decode()


IMPORTMAP_SHA = importmap_hash((STATIC / "index.html").read_text(encoding="utf-8"))
CSP = (
    f"default-src 'self'; script-src 'self' 'sha256-{IMPORTMAP_SHA}'; style-src 'self'; "
    "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
PAGE_BASE = {"base": "/static/brand", "node_css": "/static/css/node.css"}  # anagram.shell.pages
SAFE_METHODS = {"GET", "HEAD"}
WATCH_INTERVAL = 15 * 60
log = logging.getLogger("anagram.shell.ui")


def bind_local(port: int = 0) -> socket.socket:
    """A TCP socket bound to 127.0.0.1 `port` (0: a free port). Give it to the
    server (`uvicorn.Server.run(sockets=[...])`): the port stays bound from the
    choice to the start, so no other process can take it. Raise OSError when
    the port is in use. The socket listens at once: on Linux, SO_REUSEADDR
    lets a second socket bind a port that is bound but not listening."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # as uvicorn does
        sock.bind(("127.0.0.1", port))
        sock.listen(socket.SOMAXCONN)
    except OSError:
        sock.close()
        raise
    return sock


def cookie_name(port: int) -> str:
    return f"anagram_ui_{port}"


def create_ui_app(
    service: UIService,
    *,
    port: int,
    token: str,
    bus: EventBus | None = None,
    tasks: TaskRunner | None = None,
    tokens: OpenTokens | None = None,
    runtime: object | None = None,
) -> FastAPI:
    """The app of the local UI: the guard, the pages, and the API routes of
    `ui/routers/`. `tokens`: one-time open links of the app; `runtime`: the
    AppRuntime (its control secret guards /control/*). Both None: no app
    routes."""
    app = FastAPI(title="Anagram", docs_url=None, redoc_url=None, openapi_url=None)
    session = secrets.token_urlsafe(32)
    _guard(app, port, session, runtime)

    @app.exception_handler(UIError)
    def ui_error(_: Request, exc: UIError) -> JSONResponse:
        return JSONResponse({"error": exc.message, **exc.extra}, status_code=exc.status)

    _pages(app, service, port, token, session, tokens)
    ctx = UIContext(
        service, bus or EventBus(), tasks or TaskRunner(service.joined), port, runtime=runtime
    )
    app.state.ctx = ctx
    service.publish.attach(ctx.bus)  # the parts publish live events on this bus
    register_all(app, ctx)
    return app


def _guard(app: FastAPI, port: int, session: str, runtime: object | None) -> None:
    """The checks of each request (the module text): Host, Origin, the
    cookie of `/api/`, and the security headers of each answer."""
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    origins = {f"http://{h}" for h in hosts}
    cookie = cookie_name(port)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        path = request.url.path
        if request.headers.get("host", "") not in hosts:
            return JSONResponse({"error": "Unknown host."}, status_code=421)
        if path.startswith(CONTROL_PREFIX):
            # A launcher, not a page: no browser headers, a bearer (shell/app/control.py).
            refused = refuse_control(request, runtime)
            if refused is not None:
                return refused
            return await call_next(request)
        origin = request.headers.get("origin")
        if origin is not None and origin not in origins:
            return JSONResponse({"error": "Cross-origin request refused."}, status_code=403)
        if request.method not in SAFE_METHODS and origin is None:
            return JSONResponse({"error": "Missing Origin header."}, status_code=403)
        if path != "/auth/callback" and request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"error": "Cross-site request refused."}, status_code=403)
        if path.startswith("/api/"):
            got = request.cookies.get(cookie, "")
            if not hmac.compare_digest(got.encode(), session.encode()):
                return JSONResponse(
                    {
                        "error": "Open Anagram with the link that the anagram command shows.",
                        "launch": True,
                    },
                    status_code=401,
                )
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if path.startswith("/api/") or path in ("/", "/auth/callback") or path.startswith("/open/"):
            response.headers["Cache-Control"] = "no-store"
        return response


def _pages(
    app: FastAPI,
    service: UIService,
    port: int,
    token: str,
    session: str,
    tokens: OpenTokens | None,
) -> None:
    """The routes that are not API routes: the open link (it sets the
    cookie), the shell page, the ORCID callback, and the static files."""
    cookie = cookie_name(port)

    @app.get("/open/{given}")
    def open_ui(given: str) -> Response:
        target = "/" if hmac.compare_digest(given.encode(), token.encode()) else None
        if target is None and tokens is not None:
            target = tokens.redeem(given)  # a one-time link of the app
        if target is None:
            w = pages.WORDS
            return HTMLResponse(
                pages.notice(
                    w["open_old_title"],
                    w["open_old_text"],
                    action=(w["open_action"], "anagram://open"),
                    **PAGE_BASE,
                ),
                status_code=403,
            )
        resp = RedirectResponse(target, status_code=303)
        resp.set_cookie(cookie, session, httponly=True, samesite="strict", path="/")
        return resp

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/auth/callback")
    def callback(request: Request) -> HTMLResponse:
        ok = service.join.finish_signin(dict(request.query_params))
        w = pages.WORDS
        title, text = (
            (w["signed_in_title"], w["signed_in_text"])
            if ok
            else (w["signin_old_title"], w["signin_old_text"])
        )
        return HTMLResponse(
            pages.notice(
                title,
                text,
                action=(w["continue"], "/#/welcome"),
                refresh="/#/welcome" if ok else None,
                **PAGE_BASE,
            )
        )

    app.mount("/static", StaticFiles(directory=STATIC), name="static")


class UIServer:
    """One local UI server in a background thread (demo and tests). It
    binds its port when it is made (`sock`, or `bind_local(port)`), and the
    server uses that socket."""

    def __init__(
        self,
        service: UIService,
        port: int | None = None,
        *,
        sock: socket.socket | None = None,
        tokens: OpenTokens | None = None,
        runtime: object | None = None,
    ) -> None:
        import uvicorn

        self.sock = sock or bind_local(port or 0)
        self.port = self.sock.getsockname()[1]
        self.token = secrets.token_urlsafe(24)
        service.return_to = f"http://127.0.0.1:{self.port}/auth/callback"
        self.service = service
        self.app = create_ui_app(
            service, port=self.port, token=self.token, tokens=tokens, runtime=runtime
        )
        self.live = Live(service, self.app.state.ctx)  # bridges and background tasks
        cfg = uvicorn.Config(
            self.app,
            log_level="warning",
            access_log=False,  # an access line can hold an open token or a path
            timeout_graceful_shutdown=3,  # an open event stream does not block the stop
        )
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.sock]}, daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/open/{self.token}"

    def start(self, timeout: float = 15.0) -> UIServer:
        self.thread.start()
        end = time.monotonic() + timeout
        while not self.server.started:
            if time.monotonic() > end or not self.thread.is_alive():
                raise RuntimeError("the UI server did not start")
            time.sleep(0.02)
        self.live.start()
        return self

    def begin_stop(self) -> None:
        self.live.begin_stop()  # ends the open event streams and cancels tasks
        self.server.should_exit = True

    def finish_stop(self) -> None:
        self.live.finish_stop()
        if self.thread.is_alive():
            self.thread.join(timeout=10)
        self.sock.close()

    def stop(self) -> None:
        self.begin_stop()
        self.finish_stop()


def _watch(service: UIService, interval: float, stop: threading.Event) -> None:
    """Read the sources again from time to time; new items get timestamped.
    When the background helper (`anagram indexer`) runs, it does this work and
    the UI does not. An error is logged, and the next turn tries again."""
    while not stop.wait(interval):
        if not service.joined():
            continue
        try:
            if service.sources.helper_status() is None:
                service.sources.refresh()
        except Exception:  # logged; try again next time
            log.exception("source refresh failed; next try in %d s", int(interval))


def run_ui(home: str | Path, *, port: int = 0, open_browser: bool = True) -> int:
    """Start the UI for one data directory and open the browser. Blocks.

    One home has one UI: the UI takes the app lock and writes the runtime
    file of the app (`AppRuntime` with no helper), so `anagram open` finds it.
    If the app or a UI already runs for this home, open that one."""
    from anagram.shell.app.launcher import LaunchError, live_runtime, open_link
    from anagram.shell.app.runtime import AlreadyRunning, AppRuntime

    # The embedder loads its model only when the lens drafts the matching lines.
    runtime = AppRuntime(home, port=port or None, helper=False)
    runtime.handle_signals()  # before the server answers (AppRuntime.handle_signals)
    try:
        runtime.start()
    except AlreadyRunning:
        doc = live_runtime(home)
        if doc is None:
            print("Anagram already runs for this data directory.", flush=True)
            return 1
        try:
            url = open_link(doc)
        except (OSError, ValueError, KeyError, LaunchError):
            print("Anagram already runs for this data directory.", flush=True)
            return 1
        print("Anagram already runs for this data directory.")
        print(f"Open: {url}", flush=True)
        if open_browser:
            webbrowser.open(url)
        return 0
    stop = threading.Event()
    service = runtime.service
    threading.Thread(target=_watch, args=(service, WATCH_INTERVAL, stop), daemon=True).start()
    print("Anagram is running on this computer only.")
    # Flush: the link must be visible at once, also when stdout is a file.
    print(f"Open: {runtime.server.url}", flush=True)
    print("Keep this window open. Press Ctrl+C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.8, webbrowser.open, args=(runtime.server.url,)).start()
    try:
        return runtime.run_forever()
    finally:
        stop.set()


def indexer_logging(home: Path) -> Path:
    """Log the `anagram` loggers to `<home>/logs/indexer.log` and stderr."""
    import logging.handlers

    (home / "logs").mkdir(parents=True, exist_ok=True)
    path = home / "logs" / "indexer.log"
    handler = logging.handlers.RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("anagram")
    root.addHandler(handler)
    root.addHandler(logging.StreamHandler())
    root.setLevel(logging.INFO)
    return path


def run_indexer(
    home: str | Path,
    *,
    embed: bool = True,
    poll_s: float | None = None,
    once: bool = False,
    watch: bool = True,
) -> int:  # pragma: no cover - runs until stopped
    """`anagram indexer`: the background indexing helper, with no UI.
    One helper for each data directory (a lock file)."""
    import fcntl
    from contextlib import contextmanager

    from anagram.local.api import POLL_S, Indexer
    from anagram.models.embed import FastEmbedder

    home = Path(home)
    log_path = indexer_logging(home)
    lock = (home / "indexer.lock").open("w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("anagram: another helper runs for this data directory.")
        return 1
    service = UIService(home)

    @contextmanager
    def open_session():
        with service.session(index=True) as (client, idx):
            yield client, idx

    indexer = Indexer(
        open_session,
        ready=service.joined,
        embedder=FastEmbedder(cache_dir=home / "models") if embed else None,
        poll_s=poll_s or POLL_S,
        watch=watch and not once,
        ignore=(home.resolve(),),
    )
    if once:
        if not service.joined():
            print("anagram: join a community first (anagram ui).")
            return 1
        out = indexer.cycle(jobs=None)
        print(
            f"{out['new']} new, {out['changed']} changed, {out['removed']} removed;"
            f" {out['checkpoints']} checkpoints; {out['jobs']} jobs."
        )
        return 0
    stop = threading.Event()
    print("The Anagram helper is running. It indexes your sources in the background.")
    print(f"Log: {log_path}. Press Ctrl+C to stop.")
    try:
        indexer.run(stop)
    except KeyboardInterrupt:
        stop.set()
    return 0
