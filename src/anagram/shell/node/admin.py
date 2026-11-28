"""Organizer page on the node (`/admin`). Small and server-rendered.

What it shows: community name, member and organizer counts, open invites, lab
names with member counts, anchor status, and log size. What it does: makes
single-use member invite links. (Matching runs in the matching enclave of
the network, not on the node.)

It never shows user content: no findings, no profiles, no claims, no member
names or ORCID iDs, no match results. The node does not have most of these in
plain text (see spec/threat-model.md). The page shows counts and lab names
only.

Sign-in: organizers only.

- ORCID: POST /admin/login starts the identity service's ORCID flow with
  purpose "login" (members only; the same checks as `anagram login`) and sets
  a short binder cookie. ORCID returns to the one registered redirect URI,
  /auth/orcid/callback. `anagram.shell.node.app` sends the states of this page's
  flows here (`Admin.owns`). The node then finishes the flow itself (one-time
  code and PKCE verifier stay on the node). The binder cookie must match, so a
  sign-in that another site starts fails.
- Passkey: a passkey that the organizer registered on this node
  (`/auth/passkeys/register/*`). The page script runs the WebAuthn ceremony;
  the node checks it with `PasskeySignIn.login_verify`.

The admin session is a random token in an HttpOnly cookie (Path=/admin,
SameSite=Lax; Secure on https), stored as a hash, 12 hours. Each change (POST)
needs the session's CSRF token, and a POST with an Origin header from another
origin is refused. The page has a strict CSP and no third-party code.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import secrets
import threading
import time
import urllib.parse
from collections.abc import Callable
from pathlib import Path

from fastapi import APIRouter, Body, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from anagram.core.errors import FormatError, NodeError
from anagram.core.http import bearer
from anagram.core.shared_db import SharedDB
from anagram.identity.api import OOB, FlowStart, new_pid, validate_orcid
from anagram.shell import pages

FLOW_COOKIE = "anagram_admin_flow"
SESSION_COOKIE = "anagram_admin"
FLOW_TTL = 600
SESSION_TTL = 12 * 3600
MAX_ACTIVE_FLOWS = 500
RATE_WINDOW_S = 60
RATE_LIMIT = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY, binder_hash TEXT NOT NULL, verifier TEXT NOT NULL,
    expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL);
-- R8: a one-time link from the app (no ORCID). Only the hash is kept.
CREATE TABLE IF NOT EXISTS enter_codes (
    code_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""
ENTER_TTL = 120

_CSP = (
    "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'self'; "
    "connect-src 'self'; img-src 'self'; "
    "form-action 'self' https://orcid.org https://sandbox.orcid.org; "
    "frame-ancestors 'none'; base-uri 'none'"
)


def _h(*parts: str) -> str:
    return hashlib.sha256("\x00".join(("anagram/admin",) + parts).encode()).hexdigest()


class AdminDenied(Exception):
    pass


class AdminRateLimited(AdminDenied):
    pass


class Admin:
    def __init__(
        self,
        db_path: str | Path,
        identity,
        anchoring=None,
        log=None,
        clock: Callable[[], float] = time.time,
        *,
        admission,
        labs=None,
    ) -> None:
        """`admission`: the `AdmissionService` of the node (L4), for the
        invites and the invite chain. `labs`: the `LabDirectory` (L3), for the
        lab names and counts."""
        self.identity = identity
        self.labs = labs
        self.admission = admission
        self.anchoring = anchoring
        self.log = log
        self.clock = clock
        self._lock = threading.Lock()
        self._rate: dict[str, list[float]] = {}
        self._db = SharedDB(db_path)
        self._db.executescript(_SCHEMA)

    def now(self) -> int:
        return int(self.clock())

    @property
    def orcid_enabled(self) -> bool:
        return bool(getattr(self.identity.orcid_signin.orcid, "enabled", True))

    def check_rate(self, bucket: str, client_key: str) -> None:
        """Per-client sliding window rate limit for unauthenticated admin endpoints."""
        now = float(self.clock())
        cutoff = now - RATE_WINDOW_S
        key = f"{bucket}:{client_key}"
        with self._lock:
            hits = [t for t in self._rate.get(key, ()) if t > cutoff]
            if len(hits) >= RATE_LIMIT:
                self._rate[key] = hits
                raise AdminRateLimited("Too many sign-in attempts. Try again in a minute.")
            hits.append(now)
            self._rate[key] = hits
            if len(self._rate) > 1000:
                self._rate = {
                    k: [t for t in v if t > cutoff]
                    for k, v in self._rate.items()
                    if any(t > cutoff for t in v)
                }

    def _decoy_secret(self) -> bytes:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key = 'pk_decoy'").fetchone()
            if row is not None:
                return bytes.fromhex(row[0])
            raw = secrets.token_bytes(32)
            self._db.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('pk_decoy', ?)", (raw.hex(),)
            )
            row = self._db.execute("SELECT value FROM meta WHERE key = 'pk_decoy'").fetchone()
            return bytes.fromhex(row[0]) if row is not None else raw

    def _decoy_credential_id(self, orcid: str) -> str:
        digest = hmac.new(self._decoy_secret(), orcid.encode(), hashlib.sha256).digest()[:16]
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    @property
    def public_url(self) -> str:
        return self.identity.cfg.public_url.rstrip("/")

    @property
    def secure(self) -> bool:
        return self.public_url.startswith("https://")

    def origin(self) -> str:
        p = urllib.parse.urlsplit(self.public_url)
        return f"{p.scheme}://{p.netloc}"

    # ------------------------------------------------------------ sign-in

    def start_orcid(self) -> tuple[str, str]:
        """Start an ORCID sign-in with purpose "login" (members only) through the
        identity service. The page has no device key, so the node makes a
        one-time key and PKCE verifier for this flow and drops them after.
        Return (authorize URL, binder for the flow cookie)."""
        if not self.orcid_enabled:
            raise AdminDenied("ORCID is not configured on this node.")
        with self._lock:
            self._db.execute("DELETE FROM flows WHERE expires_at < ?", (self.now(),))
            count = self._db.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            if count >= MAX_ACTIVE_FLOWS:
                raise AdminRateLimited("Too many sign-in attempts. Try again in a minute.")
        binder, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        started = self.identity.orcid_signin.start(
            FlowStart(
                secrets.token_bytes(32).hex(),
                secrets.token_bytes(16).hex(),
                challenge,
                OOB,
                purpose="login",
            )
        )
        flow_id = started["flow_id"]
        with self._lock:
            self._db.execute(
                "INSERT INTO flows (id, binder_hash, verifier, expires_at) VALUES (?, ?, ?, ?)",
                (flow_id, _h("flow", flow_id, binder), verifier, self.now() + FLOW_TTL),
            )
        return started["authorize_url"], binder

    def owns(self, state: str) -> bool:
        """True if an ORCID callback `state` is an organizer-page flow."""
        row = self._db.execute("SELECT 1 FROM flows WHERE id = ?", (state,)).fetchone()
        return row is not None

    def finish_orcid(self, state: str, code: str, binder: str | None) -> tuple[str, str]:
        """Return (session token, subject). Raise AdminDenied."""
        with self._lock:
            row = self._db.execute(
                "SELECT binder_hash, verifier, expires_at FROM flows WHERE id = ?", (state,)
            ).fetchone()
            self._db.execute("DELETE FROM flows WHERE id = ?", (state,))
        if row is None or row[2] < self.now() or not binder:
            raise AdminDenied("This sign-in is unknown or expired. Start again.")
        if not hmac.compare_digest(row[0], _h("flow", state, binder)):
            raise AdminDenied("This sign-in did not start in this browser. Start again.")
        try:
            _, one_time = self.identity.orcid_signin.callback(state, code)
            out = self.identity.orcid_signin.exchange(state, one_time, row[1])
        except NodeError as exc:
            raise AdminDenied(
                "ORCID did not confirm the sign-in, or you are not a member."
            ) from exc
        token = out["session"]["token"]
        subject = self.identity.authenticate(token)
        self.identity.logout(token)  # the page needs only its own session
        return self._new_session(subject)

    def passkey_options(self, orcid: str) -> dict:
        try:
            orcid = validate_orcid(orcid.strip())
        except FormatError as exc:
            raise AdminDenied("Type a valid ORCID iD.") from exc
        # Only reveal real credentials for an organizer; unknown or non-organizer
        # ORCIDs get a deterministic synthetic credential so the response shape
        # never leaks who is a member or who has registered a passkey.
        found = self.identity.subject_for_orcid(orcid)
        subject = found if (found is not None and self._is_organizer(found)) else new_pid()
        out = self.identity.passkeys.login_options(subject)
        opts = out.get("options")
        if isinstance(opts, dict) and not opts.get("allowCredentials"):
            opts["allowCredentials"] = [
                {"id": self._decoy_credential_id(orcid), "type": "public-key"}
            ]
        return out

    def passkey_verify(self, challenge_id: str, credential: dict) -> tuple[str, str]:
        try:
            out = self.identity.passkeys.login_verify(challenge_id, credential)
        except NodeError as exc:
            raise AdminDenied("The passkey was not accepted.") from exc
        token = out["session"]["token"]
        subject = self.identity.authenticate(token)
        self.identity.logout(token)  # the page needs only its own session
        return self._new_session(subject)

    def _new_session(self, subject: str) -> tuple[str, str]:
        if not self._is_organizer(subject):
            raise AdminDenied("Only an organizer of this community can open this page.")
        token = secrets.token_urlsafe(32)
        self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (self.now(),))
        self._db.execute(
            "INSERT INTO sessions (token_hash, subject, csrf, expires_at) VALUES (?, ?, ?, ?)",
            (_h("session", token), subject, secrets.token_urlsafe(24), self.now() + SESSION_TTL),
        )
        return token, subject

    def _is_organizer(self, subject: str) -> bool:
        try:
            self.identity.require_organizer(subject)
        except NodeError:
            return False
        return True

    def session(self, token: str | None) -> tuple[str, str] | None:
        """(subject, csrf) of a valid session of a person who is still an organizer."""
        if not token:
            return None
        row = self._db.execute(
            "SELECT subject, csrf, expires_at FROM sessions WHERE token_hash = ?",
            (_h("session", token),),
        ).fetchone()
        if row is None or row[2] < self.now() or not self._is_organizer(row[0]):
            return None
        return row[0], row[1]

    def enter_link(self, subject: str) -> str:
        """A one-time link to this page for an organizer who is signed in to
        the app (the organizer needs no ORCID iD). Two minutes, one use."""
        if not self._is_organizer(subject):
            raise AdminDenied("Only an organizer of this community can open this page.")
        code = secrets.token_urlsafe(32)
        self._db.execute("DELETE FROM enter_codes WHERE expires_at < ?", (self.now(),))
        self._db.execute(
            "INSERT INTO enter_codes (code_hash, subject, expires_at) VALUES (?, ?, ?)",
            (_h("enter", code), subject, self.now() + ENTER_TTL),
        )
        return f"{self.public_url}/admin/enter?code={code}"

    def enter(self, code: str) -> tuple[str, str]:
        """Use a one-time link. Return (session token, subject)."""
        with self._lock:
            key = _h("enter", str(code))
            row = self._db.execute(
                "SELECT subject, expires_at FROM enter_codes WHERE code_hash = ?", (key,)
            ).fetchone()
            self._db.execute("DELETE FROM enter_codes WHERE code_hash = ?", (key,))
        if row is None or row[1] < self.now():
            raise AdminDenied("This link is used or expired. Open the page again from Anagram.")
        return self._new_session(row[0])

    def logout(self, token: str | None) -> None:
        if token:
            self._db.execute("DELETE FROM sessions WHERE token_hash = ?", (_h("session", token),))

    # -------------------------------------------------------------- status

    def status(self) -> dict:
        out: dict = {"community": self.identity.cfg.community}
        out.update(self.identity.community_stats())
        out["labs"] = self.labs.counts() if self.labs is not None else []
        out["open_invites"] = self.admission.open_invites()
        # Names only: no internal id leaves in the page (experience rule 9).
        out["invite_chain"] = [
            {"by_name": r["by_name"], "invited": r["by"] is not None, "name": r["name"]}
            for r in self.admission.invite_chain()
        ]
        if self.log is not None:
            out["log_size"] = self.log.store.size()
        if self.anchoring is not None:
            out["anchors"] = self.anchoring.status()
        return out


# ------------------------------------------------------------------ pages


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'s' if n != 1 else ''}"


# The look is the brand: anagram.shell.pages and ui/static/css/node.css. This module
# has no inline style, so the CSP has no 'unsafe-inline'.
_STYLE = ""


def _page(title: str, body: str, *, script: str | None = None) -> str:
    return pages.page(title, body, script=script, wide=True)


def _facts(rows) -> str:
    """Label and value rows (the `Facts` look of the local UI)."""
    esc = html.escape
    return (
        "<table class=ag-node-facts>"
        + "".join(f"<tr><th>{esc(k)}</th><td>{esc(str(v))}</td></tr>" for k, v in rows)
        + "</table>"
    )


def login_page(community: str, message: str = "", *, orcid_enabled: bool = True) -> str:
    msg = f"<p class=ag-node-warn role=alert>{html.escape(message)}</p>" if message else ""
    orcid_form = (
        "<form class=ag-node-form method=post action=/admin/login>"
        "<button class='rf-ui-button rf-ui-button--secondary'>Sign in with ORCID</button>"
        "</form>"
        if orcid_enabled
        else ""
    )
    return _page(
        f"{community}: organizer sign-in",
        "<p class=ag-node-eyebrow>Organizer page</p>"
        f"<h1 class=ag-node-title>{html.escape(community)}</h1>"
        "<p class=ag-node-lead>Only an organizer of this community can sign in. "
        "Open this page from Anagram: Account, then Organizer page.</p>"
        f"{msg}"
        f"{orcid_form}"
        "<form id=pk class='ag-node-form ag-node-or'>"
        "<div class=ag-node-inline><p class=rf-ui-field><label for=pk-orcid>ORCID iD</label>"
        "<input class=rf-ui-input id=pk-orcid name=orcid required autocomplete=username "
        "placeholder=0000-0000-0000-0000></p>"
        "<button class='rf-ui-button rf-ui-button--secondary'>Sign in with a passkey</button>"
        "</div></form>"
        "<p id=pkmsg class=ag-node-warn role=alert></p>",
        script="/admin/passkey.js",
    )


def dashboard(status: dict, subject: str, csrf: str, new_invite: str | None = None) -> str:
    # `subject` is an internal id. It does not show on the page (experience rule 9).
    esc = html.escape
    rows = [
        ("Members", status["members"]),
        ("Organizers", status["organizers"]),
        ("Open invites", status["open_invites"]),
        ("Labs", len(status["labs"])),
    ]
    if "log_size" in status:
        rows.append(("Log entries", status["log_size"]))
    labs = (
        _facts((lab["name"], _count(lab["members"], "member")) for lab in status["labs"])
        if status["labs"]
        else "<p class=ag-node-empty>No labs yet.</p>"
    )
    match_html = (
        "<p class=ag-node-empty>Matching runs in the matching enclave of the network, not on "
        "this node. This node only passes on sealed messages. Run <code>anagram node enclave "
        "status</code> to check the connection.</p>"
    )
    a = status.get("anchors")
    anchor_html = (
        "<p class=ag-node-empty>No background anchors. This is a local development node.</p>"
    )
    if a:
        counts = ", ".join(f"{k} {v}" for k, v in sorted(a["counts"].items())) or "Not yet"
        anchor_rows = [
            ("Anchors", ", ".join(a["anchors"])),
            ("Last anchored log size", a["last_anchored_size"] or "Not yet"),
            ("Jobs", counts),
        ]
        if a["last_error"]:
            anchor_rows.append(("Last error (the node tries again)", a["last_error"]))
        anchor_html = _facts(anchor_rows)
    chain = status.get("invite_chain") or []
    chain_html = (
        _facts(
            (
                row["name"],
                f"Invited by {row['by_name']}" if row["invited"] else "Invited by the node",
            )
            for row in chain
        )
        if chain
        else "<p class=ag-node-empty>No members yet.</p>"
    )
    invite = ""
    if new_invite:
        invite = (
            "<div class=ag-node-code><p class=ag-node-label>New invite link. One person can "
            "use it one time. This page does not show it again.</p>"
            f"<pre>{esc(new_invite)}</pre></div>"
        )
    token = f"<input type=hidden name=csrf value='{esc(csrf)}'>"
    return _page(
        f"{status['community']}: organizer page",
        "<p class=ag-node-eyebrow>Organizer page</p>"
        f"<h1 class=ag-node-title>{esc(status['community'])}</h1>"
        "<p class=ag-node-lead>This page shows counts and lab names. It never shows findings, "
        "profiles, or match results.</p>"
        f"<h2 class=ag-node-section>Invite a member</h2>{invite}"
        f"<form class=ag-node-form method=post action=/admin/invites>{token}"
        "<div class=ag-node-inline><p class=rf-ui-field><label for=days>Days until the link "
        "expires</label><input class=rf-ui-input id=days name=days type=number min=1 max=30 "
        "value=7></p><button class=rf-ui-button>Make an invite link</button></div></form>"
        f"<h2 class=ag-node-section>Community</h2>{_facts(rows)}"
        f"<h2 class=ag-node-section>Who invited whom</h2>{chain_html}"
        f"<h2 class=ag-node-section>Labs</h2><div id=ag-admin-labs data-csrf='{esc(csrf)}'>{labs}</div><script type=module src=/brand/node/admin_labs.js></script>"
        f"<h2 class=ag-node-section>Matching</h2>{match_html}"
        f"<h2 class=ag-node-section>Time anchors</h2>{anchor_html}"
        f"<form class='ag-node-form ag-node-foot' method=post action=/admin/logout>{token}"
        "<button class='rf-ui-button rf-ui-button--quiet'>Sign out</button></form>",
    )


PASSKEY_JS = """
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') +
  '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const enc = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
  .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
const form = document.getElementById('pk');
const msg = document.getElementById('pkmsg');
const post = (path, body) => fetch(path, {method: 'POST', credentials: 'same-origin',
  headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  msg.textContent = '';
  try {
    const r = await post('/admin/passkey/options', {orcid: form.orcid.value.trim()});
    if (!r.ok) throw new Error((await r.json()).detail);
    const {challenge_id, options} = await r.json();
    options.challenge = dec(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map(
      (c) => ({...c, id: dec(c.id)}));
    const cred = await navigator.credentials.get({publicKey: options});
    const res = cred.response;
    const v = await post('/admin/passkey/verify', {challenge_id, credential: {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type, response: {
        clientDataJSON: enc(res.clientDataJSON),
        authenticatorData: enc(res.authenticatorData),
        signature: enc(res.signature),
        userHandle: res.userHandle ? enc(res.userHandle) : null}}});
    if (!v.ok) throw new Error((await v.json()).detail);
    location.href = '/admin';
  } catch (err) {
    msg.textContent = err.message || 'The passkey did not sign you in. Try again.';
  }
});
"""


# ----------------------------------------------------------------- routes


def _headers(resp: Response) -> Response:
    resp.headers["Content-Security-Policy"] = _CSP
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def _html(text: str, status: int = 200) -> Response:
    return _headers(HTMLResponse(text, status_code=status))


def same_origin(admin: Admin, request: Request, required: bool = False) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return not required
    return origin == admin.origin()


def current(admin: Admin, request: Request):
    """(subject, csrf) of the organizer session of this request, or None."""
    return admin.session(request.cookies.get(SESSION_COOKIE))


def checked(admin: Admin, request: Request, csrf: str, required: bool = False):
    """The session, if the request is same-origin and has its CSRF value."""
    sess = current(admin, request)
    if (
        sess is None
        or not same_origin(admin, request, required)
        or not hmac.compare_digest(sess[1], csrf)
    ):
        return None
    return sess


def json_headers(resp: Response) -> Response:
    """The headers of the organizer pages, for a JSON answer."""
    return _headers(resp)


def _client_key(request: Request) -> str:
    return request.client.host if request.client and request.client.host else "unknown"


def _login_html(admin: Admin, message: str = "", status: int = 200) -> Response:
    return _html(
        login_page(admin.identity.cfg.community, message, orcid_enabled=admin.orcid_enabled),
        status,
    )


def admin_router(admin: Admin) -> APIRouter:  # noqa: C901, PLR0915
    router = APIRouter(prefix="/admin")

    def set_session(resp: Response, token: str) -> None:
        resp.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=SESSION_TTL,
            path="/admin",
            httponly=True,
            secure=admin.secure,
            samesite="lax",
        )

    @router.get("")
    def page(request: Request) -> Response:
        sess = current(admin, request)
        if sess is None:
            return _login_html(admin)
        return _html(dashboard(admin.status(), sess[0], sess[1]))

    @router.get("/enter")
    def enter(code: str = "") -> Response:
        try:
            token, _ = admin.enter(code)
        except AdminDenied as exc:
            return _login_html(admin, str(exc), 403)
        resp = RedirectResponse("/admin", status_code=303)
        set_session(resp, token)
        return _headers(resp)

    @router.post("/enter-link")
    def enter_link(authorization: str | None = Header(default=None)) -> Response:
        token = bearer(authorization)
        try:
            subject = admin.identity.authenticate(token)
            url = admin.enter_link(subject)
        except (NodeError, AdminDenied) as exc:
            return json_headers(JSONResponse({"detail": str(exc)}, status_code=403))
        return json_headers(JSONResponse({"url": url}))

    @router.get("/passkey.js")
    def passkey_js() -> Response:
        return _headers(Response(PASSKEY_JS, media_type="text/javascript"))

    @router.post("/login")
    def login(request: Request) -> Response:
        if not same_origin(admin, request, required=True):
            return _login_html(admin, "This sign-in came from another site. Start again here.", 403)
        if not admin.orcid_enabled:
            return _login_html(admin, "ORCID is not configured on this node.", 503)
        try:
            admin.check_rate("login", _client_key(request))
            url, binder = admin.start_orcid()
        except AdminRateLimited as exc:
            return _login_html(admin, str(exc), 429)
        except AdminDenied as exc:
            return _login_html(admin, str(exc), 403)
        resp = RedirectResponse(url, status_code=303)
        resp.set_cookie(
            FLOW_COOKIE,
            binder,
            max_age=FLOW_TTL,
            path="/auth/orcid/callback",
            httponly=True,
            secure=admin.secure,
            samesite="lax",
        )
        return _headers(resp)

    @router.post("/passkey/options")
    def pk_options(request: Request, body: dict = Body(...)) -> Response:
        if not same_origin(admin, request, required=True):
            return JSONResponse({"detail": "wrong origin"}, status_code=403)
        try:
            admin.check_rate("passkey", _client_key(request))
            return JSONResponse(admin.passkey_options(str(body.get("orcid", ""))))
        except AdminRateLimited as exc:
            return JSONResponse({"detail": str(exc)}, status_code=429)
        except (AdminDenied, NodeError) as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)

    @router.post("/passkey/verify")
    def pk_verify(request: Request, body: dict = Body(...)) -> Response:
        if not same_origin(admin, request, required=True):
            return JSONResponse({"detail": "wrong origin"}, status_code=403)
        try:
            token, _ = admin.passkey_verify(
                str(body.get("challenge_id", "")), body.get("credential") or {}
            )
        except AdminDenied as exc:
            return JSONResponse({"detail": str(exc)}, status_code=403)
        resp = JSONResponse({"status": "signed_in"})
        set_session(resp, token)
        return resp

    async def form(request: Request) -> dict[str, str]:
        """URL-encoded form fields (small forms only; no extra dependency)."""
        raw = (await request.body())[:4096].decode("utf-8", "replace")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    @router.post("/invites")
    async def invite(request: Request) -> Response:
        fields = await form(request)
        sess = checked(admin, request, fields.get("csrf", ""))
        if sess is None:
            return _login_html(admin, "Sign in again.", 403)
        try:
            days = min(max(float(fields.get("days", "7")), 1), 30)
        except ValueError:
            days = 7
        link = admin.admission.create_invite(sess[0], days)["invite_url"]
        return _html(dashboard(admin.status(), sess[0], sess[1], new_invite=link))

    @router.post("/logout")
    async def logout(request: Request) -> Response:
        if checked(admin, request, (await form(request)).get("csrf", "")) is None:
            return _login_html(admin, "Sign in again.", 403)
        admin.logout(request.cookies.get(SESSION_COOKIE))
        resp = RedirectResponse("/admin", status_code=303)
        resp.delete_cookie(SESSION_COOKIE, path="/admin")
        return _headers(resp)

    return router


def orcid_callback(admin: Admin, request: Request, state: str, code: str) -> Response:
    """The organizer-page part of /auth/orcid/callback (see `Admin.owns`)."""
    try:
        token, _ = admin.finish_orcid(state, code, request.cookies.get(FLOW_COOKIE))
    except AdminDenied as exc:
        resp = _login_html(admin, str(exc), 403)
    else:
        resp = _headers(RedirectResponse("/admin", status_code=303))
        resp.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=SESSION_TTL,
            path="/admin",
            httponly=True,
            secure=admin.secure,
            samesite="lax",
        )
    resp.delete_cookie(FLOW_COOKIE, path="/auth/orcid/callback")
    return resp
