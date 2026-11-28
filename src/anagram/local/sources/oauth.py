"""OAuth for an app on the person's computer (RFC 8252 with RFC 7636 PKCE).

    flow = OAuthFlow(PROVIDERS["google"], client, scopes, http)
    url = flow.start()          # open it in the system browser
    tokens, identity = flow.finish()

Rules:

- The redirect goes to a one-use HTTP listener on 127.0.0.1
  (`LoopbackReceiver`). It is not a route of the local UI: it has no cookie,
  reads no state, and changes nothing but its own flow. It accepts one
  `GET /oauth/callback` with the expected `state` (a constant-time compare)
  and stops after that request or after `timeout_s`.
- PKCE S256 (Google). An authorization code has no value without the
  verifier, so another local app that sees the code cannot use it.
- An installed app cannot keep a client secret. The secret of a "Desktop app"
  client is not confidential (Google documents this). Never put a real
  client secret in the repository.
- A token never goes into a log line, an exception text, or an event.

OAuth client resolution, in order (`resolve_client`):

1. A client that a lab set in its settings (section `oauth_clients` of the
   lab settings record; `labs.lab_policy(lab_id).oauth_clients`), from the
   first lab of `labs.lab_list()` that has one.
2. A client in the build: `anagram/_oauth_clients.json` (the release build
   writes it; it is not in the repository).
3. A client in `<home>/oauth-clients.json` (developers who run from source).

All three files and sections have the shape
`{"google": {"client_id": ..., "client_secret": ...}, "notion": {...}}`.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import html
import json
import logging
import secrets
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING

from anagram.core.errors import ClientError
from anagram.local.sources.http import HttpResponse, HttpTransport, SourceFault

if TYPE_CHECKING:
    from anagram.local.ports import LabContext

log = logging.getLogger("anagram.local.index")

CALLBACK_PATH = "/oauth/callback"
FLOW_TIMEOUT_S = 300.0
LOOPBACK = "127.0.0.1"  # the receiver binds this address only
BUILD_FILE = Path(str(resources.files("anagram").joinpath("_oauth_clients.json")))
USER_FILE = "oauth-clients.json"
ORIGINS = ("lab", "build", "user")


class OAuthError(Exception):
    """A sign-in that did not complete. `code` is one of `denied`, `expired`,
    `cancelled`, `scope_missing`, `bad_response`, `refused`. The text holds no
    token and no code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class OAuthClient:
    client_id: str
    client_secret: str | None  # not confidential for an installed app
    origin: str  # "lab" | "build" | "user"

    def __repr__(self) -> str:  # the secret never goes into a log line
        return f"OAuthClient(client_id={self.client_id!r}, origin={self.origin!r})"


@dataclass(frozen=True)
class OAuthProvider:
    name: str  # google | notion
    authorize_url: str
    token_url: str
    revoke_url: str | None
    api_hosts: tuple[str, ...]  # an access token goes only to these hosts
    pkce: bool
    redirect_ports: tuple[int, ...]  # () = any free port
    token_auth: str  # "body" (form body, Google) | "basic" (HTTP Basic and JSON, Notion)
    extra_authorize: Mapping[str, str] = field(default_factory=dict)
    redirect_host: str = LOOPBACK  # the host name in the redirect URI
    identity_scopes: tuple[str, ...] = ()  # scopes that give the identity of the person


GOOGLE = OAuthProvider(
    name="google",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    token_url="https://oauth2.googleapis.com/token",  # noqa: S106
    revoke_url="https://oauth2.googleapis.com/revoke",
    api_hosts=("www.googleapis.com", "gmail.googleapis.com"),
    pkce=True,
    redirect_ports=(),
    token_auth="body",  # noqa: S106
    extra_authorize={"access_type": "offline", "include_granted_scopes": "true"},
    identity_scopes=("openid", "email"),
)

# Notion: a public integration. The redirect URI must match a registered URI
# exactly, so the receiver tries the three registered ports in order. Verify
# with a live check: `http://localhost` is accepted, there is no PKCE, the
# refresh token and the revoke endpoint.
NOTION = OAuthProvider(
    name="notion",
    authorize_url="https://api.notion.com/v1/oauth/authorize",
    token_url="https://api.notion.com/v1/oauth/token",  # noqa: S106
    revoke_url="https://api.notion.com/v1/oauth/revoke",
    api_hosts=("api.notion.com",),
    pkce=False,
    redirect_ports=(53682, 53683, 53684),
    token_auth="basic",  # noqa: S106
    extra_authorize={"owner": "user"},
    redirect_host="localhost",
)

PROVIDERS: dict[str, OAuthProvider] = {p.name: p for p in (GOOGLE, NOTION)}

DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

# Source kind -> (provider, scopes that the kind needs). Read-only and the
# narrowest scope that does the work.
KIND_SCOPES: dict[str, tuple[str, tuple[str, ...]]] = {
    "gdrive": ("google", (DRIVE_SCOPE,)),
    "gmail": ("google", (GMAIL_SCOPE,)),
    "notion": ("notion", ()),
}


# ------------------------------------------------------------------- PKCE


def pkce_challenge(verifier: str) -> str:
    """BASE64URL(SHA-256(verifier)) with no padding (RFC 7636, S256)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def new_verifier() -> str:
    """64 random characters of the RFC 7636 unreserved set."""
    return secrets.token_urlsafe(48)[:64]


def new_state() -> str:
    return secrets.token_urlsafe(32)  # 32 random bytes


# --------------------------------------------------------------- receiver

_PAGE = (
    "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
    "<title>Anagram</title><style>body{{font:16px/1.5 system-ui,sans-serif;"
    "margin:15vh auto;max-width:28rem;padding:0 1rem;color:#1a1a1a}}</style></head>"
    "<body><p>{text}</p></body></html>"
)
_DONE = "You can close this tab and go back to Anagram."
_REFUSED = "Anagram did not accept this sign-in. Start again in Anagram."


class _IPv6HTTPServer(HTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        with contextlib.suppress(OSError, AttributeError):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class LoopbackReceiver:
    """A one-use HTTP listener on 127.0.0.1 (plus ::1 when `host_name` is
    `localhost`). It accepts one GET /oauth/callback with the expected `state`.
    It answers with a small static page and stops. It stops after `timeout_s`
    (300) in each case.

    The bind address is always loopback; a caller cannot change it. With
    `ports`, the receiver takes the first free port of the list (a provider
    that needs a registered redirect URI). With no ports, the system gives a
    free port."""

    def __init__(
        self,
        ports: tuple[int, ...] = (),
        *,
        state: str | None = None,
        host_name: str = LOOPBACK,
        timeout_s: float = FLOW_TIMEOUT_S,
    ) -> None:
        self._expected = state
        self._result: dict | None = None
        self._done = threading.Event()
        self._lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._closed = False
        self._host_name = host_name
        self.server, self._v6_server = self._bind(ports)
        self._thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()
        self._v6_thread: threading.Thread | None = None
        if self._v6_server is not None:
            self._v6_thread = threading.Thread(
                target=self._v6_server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            )
            self._v6_thread.start()
        self._timer: threading.Timer | None = None
        if timeout_s > 0:
            self._timer = threading.Timer(timeout_s, self.close)
            self._timer.daemon = True
            self._timer.start()

    def _bind(self, ports: tuple[int, ...]) -> tuple[HTTPServer, HTTPServer | None]:
        handle = self._handle  # the request handler class calls it

        class Handler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(5.0)

            def do_GET(self) -> None:  # the name of the stdlib hook
                ok = handle(self.path)
                body = _PAGE.format(text=html.escape(_DONE if ok else _REFUSED)).encode()
                self.send_response(200 if ok else 400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:
                return  # the request line holds the code; it never goes to a log

        last: OSError | None = None
        for port in ports or (0,):
            try:
                v4 = HTTPServer((LOOPBACK, port), Handler)
            except OSError as exc:
                last = exc
                continue
            v6: HTTPServer | None = None
            if self._host_name == "localhost":
                with contextlib.suppress(OSError):
                    v6 = _IPv6HTTPServer(("::1", int(v4.server_address[1])), Handler)
            return v4, v6
        raise OAuthError("refused", "no free port for the sign-in") from last

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def redirect_uri(self) -> str:
        return f"http://{self._host_name}:{self.port}{CALLBACK_PATH}"

    def expect(self, state: str) -> None:
        self._expected = state

    def _handle(self, path: str) -> bool:
        parts = urllib.parse.urlsplit(path)
        if parts.path != CALLBACK_PATH:
            return False
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        expected = self._expected
        got = query.get("state", "")
        if not expected or not hmac.compare_digest(got.encode(), expected.encode()):
            return False  # a forged or old callback; the flow continues to wait
        with self._lock:
            if self._result is not None:
                return False  # one use
            if "code" in query and query["code"]:
                self._result = {"code": query["code"]}
            else:
                self._result = {"error": query.get("error") or "no_code"}
        self._done.set()
        threading.Thread(target=self.close, daemon=True).start()
        return True

    def wait(self, state: str | None = None, timeout_s: float = FLOW_TIMEOUT_S) -> dict:
        """`{"code": ...}` or `{"error": ...}`. A timeout gives
        `{"error": "timeout"}`. The receiver is closed after this call."""
        if state is not None:
            self.expect(state)
        got = self._done.wait(timeout_s)
        self.close()
        with self._lock:
            if not got or self._result is None:
                self._result = self._result or {"error": "timeout"}
            return dict(self._result)

    def cancel(self) -> None:
        with self._lock:
            if self._result is None:
                self._result = {"error": "cancelled"}
        self._done.set()
        self.close()

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        if self._timer is not None:
            self._timer.cancel()
        self.server.shutdown()
        self.server.server_close()
        if self._v6_server is not None:
            self._v6_server.shutdown()
            self._v6_server.server_close()


# ------------------------------------------------------------------ tokens


def _form(data: Mapping[str, str]) -> bytes:
    return urllib.parse.urlencode(data).encode()


def token_request(
    provider: OAuthProvider, client: OAuthClient, fields: Mapping[str, str]
) -> tuple[dict[str, str], bytes]:
    """Headers and body of a call to the token endpoint."""
    if provider.token_auth == "basic":  # noqa: S105
        raw = f"{client.client_id}:{client.client_secret or ''}".encode()
        headers = {
            "Authorization": "Basic " + base64.b64encode(raw).decode(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return headers, json.dumps(dict(fields)).encode()
    data = {"client_id": client.client_id, **fields}
    if client.client_secret:
        data["client_secret"] = client.client_secret
    return {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, (
        _form(data)
    )


def token_error(resp: HttpResponse) -> str:
    """The OAuth `error` value of a refused token call (RFC 6749 5.2)."""
    try:
        body = resp.json()
    except SourceFault:
        return ""
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        return body["error"]
    return ""


def parse_tokens(body: object, now: float, *, scopes: tuple[str, ...] = (), old=None):
    """A `TokenSet` from a token response. A refresh response with no
    `refresh_token` keeps the old refresh token."""
    from anagram.local.sources.credentials import TokenSet

    if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
        raise OAuthError("bad_response", "the token answer has no access token")
    expires = body.get("expires_in")
    granted = body.get("scope")
    if isinstance(granted, str) and granted.strip():
        scopes = tuple(sorted(set(granted.split())))
    elif old is not None:
        scopes = old.scopes
    refresh = body.get("refresh_token")
    if not isinstance(refresh, str) or not refresh:
        refresh = old.refresh_token if old is not None else None
    return TokenSet(
        access_token=body["access_token"],
        expires_at=(now + float(expires)) if isinstance(expires, int | float) else None,
        refresh_token=refresh,
        scopes=tuple(scopes),
        token_type=str(body.get("token_type") or "Bearer"),
    )


def _jwt_claims(token: str) -> dict:
    """The claims of an ID token. The token came straight from the token
    endpoint over TLS, so the signature check is not necessary (OpenID
    Connect Core 3.1.3.7, item 6)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError):
        raise OAuthError("bad_response", "the ID token does not parse") from None
    if not isinstance(claims, dict):
        raise OAuthError("bad_response", "the ID token does not parse")
    return claims


def identity_of(provider: OAuthProvider, body: dict) -> dict:
    """`{"external_id", "label"}` of the person from a token response."""
    if provider.name == "google":
        claims = _jwt_claims(str(body.get("id_token") or ""))
        sub, email = claims.get("sub"), claims.get("email")
        if not isinstance(sub, str) or not sub:
            raise OAuthError("bad_response", "the ID token has no subject")
        return {"external_id": sub, "label": email if isinstance(email, str) else sub}
    bot = body.get("bot_id")
    if not isinstance(bot, str) or not bot:
        raise OAuthError("bad_response", "the token answer has no bot ID")
    name = body.get("workspace_name")
    return {"external_id": bot, "label": name if isinstance(name, str) and name else "Notion"}


# -------------------------------------------------------------------- flow


class OAuthFlow:
    """One sign-in. `start()` gives the authorize URL and starts the
    receiver. `finish()` waits for the redirect, exchanges the code, and
    gives the tokens and the identity."""

    def __init__(
        self,
        provider: OAuthProvider,
        client: OAuthClient,
        scopes: list[str],
        http: HttpTransport,
        *,
        login_hint: str | None = None,
        first_grant: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.provider = provider
        self.client = client
        self.scopes = sorted(set(scopes) | set(provider.identity_scopes))
        self.http = http
        self.login_hint = login_hint
        self.first_grant = first_grant
        self.clock = clock
        self.receiver: LoopbackReceiver | None = None
        self._verifier = new_verifier() if provider.pkce else None
        self._state = new_state()

    def start(self) -> str:
        if self.receiver is not None:
            raise OAuthError("refused", "this flow has started")
        self.receiver = LoopbackReceiver(
            self.provider.redirect_ports, state=self._state, host_name=self.provider.redirect_host
        )
        params: dict[str, str] = {
            "client_id": self.client.client_id,
            "redirect_uri": self.receiver.redirect_uri,
            "response_type": "code",
            "state": self._state,
        }
        if self.scopes:
            params["scope"] = " ".join(self.scopes)
        if self._verifier is not None:
            params["code_challenge"] = pkce_challenge(self._verifier)
            params["code_challenge_method"] = "S256"
        params.update(self.provider.extra_authorize)
        if self.provider.name == "google":
            # Consent again on the first grant, so that Google gives a refresh token.
            if self.first_grant:
                params["prompt"] = "consent"
            if self.login_hint:
                params["login_hint"] = self.login_hint
        return self.provider.authorize_url + "?" + urllib.parse.urlencode(params)

    def finish(self, timeout_s: float = FLOW_TIMEOUT_S) -> tuple[object, dict]:
        """Tokens (`TokenSet`) and identity (`{"external_id", "label"}`)."""
        if self.receiver is None:
            raise OAuthError("refused", "the flow has not started")
        got = self.receiver.wait(self._state, timeout_s)
        if "code" not in got:
            error = got.get("error")
            if error == "timeout":
                raise OAuthError("expired")
            if error == "cancelled":
                raise OAuthError("cancelled")
            if error == "access_denied":
                raise OAuthError("denied")
            raise OAuthError("refused", "the provider did not give a code")
        fields = {
            "code": got["code"],
            "grant_type": "authorization_code",
            "redirect_uri": self.receiver.redirect_uri,
        }
        if self._verifier is not None:
            fields["code_verifier"] = self._verifier
        headers, body = token_request(self.provider, self.client, fields)
        resp = self.http("POST", self.provider.token_url, headers, body)
        if resp.status != 200:
            raise OAuthError("refused", f"the token call gave HTTP {resp.status}")
        data = resp.json()
        tokens = parse_tokens(data, self.clock(), scopes=tuple(self.scopes))
        # Google names the identity scopes in another form in its answer
        # (`email` -> `.../auth/userinfo.email`), so only the scopes of the
        # source are compared.
        missing = (
            [
                s
                for s in self.scopes
                if s not in tokens.scopes and s not in self.provider.identity_scopes
            ]
            if self.provider.name == "google"
            else []
        )
        if missing:
            # Google lets a person clear a scope in the consent screen.
            raise OAuthError("scope_missing", "a scope that the source needs was not given")
        return tokens, identity_of(self.provider, data)

    def cancel(self) -> None:
        if self.receiver is not None:
            self.receiver.cancel()


def revoke(
    provider: OAuthProvider, client: OAuthClient | None, tokens, http: HttpTransport
) -> bool:
    """Ask the provider to remove the grant. True if the provider confirmed.
    Google: the refresh token removes the whole grant of the person for this
    client. A fault (offline) gives False; the caller deletes the local token
    in each case."""
    if provider.revoke_url is None:
        return False
    token = tokens.refresh_token or tokens.access_token
    try:
        if provider.token_auth == "basic":  # noqa: S105
            if client is None:
                return False
            headers, body = token_request(provider, client, {"token": token})
        else:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            body = _form({"token": token})
        resp = http("POST", provider.revoke_url, headers, body)
    except SourceFault:
        return False
    return resp.status == 200


# ------------------------------------------------------- client resolution


def _client_from(section: object, provider: str, origin: str) -> OAuthClient | None:
    if not isinstance(section, Mapping):
        return None
    entry = section.get(provider)
    if not isinstance(entry, Mapping):
        return None
    cid = entry.get("client_id")
    if not isinstance(cid, str) or not cid:
        return None
    secret = entry.get("client_secret")
    return OAuthClient(cid, secret if isinstance(secret, str) and secret else None, origin)


def _read_file(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        log.warning("an OAuth client file does not parse: %s", path.name)
        return None


def lab_clients(labs: LabContext, provider: str) -> list[OAuthClient]:
    """The clients that the labs of the member set (section `oauth_clients`
    of the lab settings record), in the order of `labs.lab_list()`. A
    lab whose policy is not on this computer (`ClientError`) is skipped."""
    out = []
    try:
        rows = labs.lab_list()
    except (ClientError, OSError, ValueError) as exc:
        log.warning("lab list for OAuth clients failed: %s", type(exc).__name__)
        return []
    for lab in rows or []:
        lab_id = lab.get("lab_id") if isinstance(lab, Mapping) else None
        if not lab_id:
            continue
        try:
            section = labs.lab_policy(lab_id).oauth_clients
        except ClientError as exc:  # one lab must not stop the others
            log.warning("lab policy for OAuth clients failed: %s", type(exc).__name__)
            continue
        found = _client_from(section, provider, "lab")
        if found is not None:
            out.append(found)
    return out


def candidate_clients(
    provider: str,
    *,
    labs: LabContext | None = None,
    home: str | Path | None = None,
    build_file: Path = BUILD_FILE,
) -> list[OAuthClient]:
    """Each client for a provider, in the order of resolution."""
    out = lab_clients(labs, provider) if labs is not None else []
    found = _client_from(_read_file(build_file), provider, "build")
    if found is not None:
        out.append(found)
    if home is not None:
        found = _client_from(_read_file(Path(home) / USER_FILE), provider, "user")
        if found is not None:
            out.append(found)
    return out


ClientResolver = Callable[..., OAuthClient | None]


def client_resolver(
    labs: LabContext | None = None, home: str | Path | None = None, build_file: Path = BUILD_FILE
) -> ClientResolver:
    """`resolve(provider, client_id=None)`: the first client for the
    provider, or with `client_id` the client with that ID (the client of an
    existing grant). None if there is no such client."""

    def resolve(provider: str, client_id: str | None = None) -> OAuthClient | None:
        for c in candidate_clients(provider, labs=labs, home=home, build_file=build_file):
            if client_id is None or c.client_id == client_id:
                return c
        return None

    return resolve
