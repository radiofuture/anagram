"""Accounts and tokens of connected sources (Google, Notion, Zotero web).

    creds = CredentialStore(keystore, store, http, clients)
    acct = creds.save("google", sub, email, client_id, tokens)
    resp = creds.request(acct.id, "GET", "https://www.googleapis.com/drive/v3/...")

Rules:

- A token is only in the keystore entry `acct-<account id>` (UTF-8 JSON of
  `TokenSet`). The `account` table (in SQLCipher) holds the label, the
  scopes, and the status, never a token. Each write is
  `keystore.put(name, value, overwrite=True)` and a removal is
  `keystore.delete(name)`, so no old token value stays on the disk.
- An access token goes only to the hosts of its provider
  (`OAuthProvider.api_hosts`). `request` and `auth_headers` refuse each
  other host.
- A token is never in a config, a log line, an event, or an error text.
- One account for each (provider, OAuth client, person). A second source of
  the same provider adds scopes to the same grant, because a Google revoke
  removes the whole grant of that person for that client.
- `access_token` refreshes when less than 120 seconds remain. A process lock
  stops a double refresh in one process. A refresh that gives `invalid_grant`
  reads the keystore one more time (another process can have refreshed with a
  rotated refresh token), then marks the account `expired` and raises
  `SourceFault("auth_expired")`.
"""

from __future__ import annotations

import json
import logging
import secrets
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from anagram.core.timefmt import format_time
from anagram.local.index.store import IndexStore, dumps, loads
from anagram.local.sources.http import (
    HttpResponse,
    HttpTransport,
    SourceFault,
    call_with_backoff,
    classify_status,
)
from anagram.local.sources.oauth import (
    PROVIDERS,
    OAuthClient,
    parse_tokens,
    token_error,
    token_request,
)
from anagram.local.sources.oauth import revoke as provider_revoke

if TYPE_CHECKING:
    from anagram.identity.api import Keystore

log = logging.getLogger("anagram.local.index")

REFRESH_BEFORE_S = 120.0
KEY_PREFIX = "acct-"
API_KEY_PROVIDERS = frozenset({"zotero"})
API_KEY_HOSTS = {"zotero": ("api.zotero.org",)}
STATUSES = ("ok", "expired", "revoked")

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_LOCK = threading.Lock()


def _lock(account_id: str) -> threading.Lock:
    with _LOCKS_LOCK:
        return _LOCKS.setdefault(account_id, threading.Lock())


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    expires_at: float | None  # epoch seconds; None: does not expire
    refresh_token: str | None
    scopes: tuple[str, ...]
    token_type: str = "Bearer"  # noqa: S105

    def __repr__(self) -> str:  # a token never goes into a log line
        return f"TokenSet(expires_at={self.expires_at!r}, scopes={self.scopes!r})"

    def to_bytes(self) -> bytes:
        d = asdict(self)
        d["scopes"] = list(self.scopes)
        return json.dumps(d, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, raw: bytes) -> TokenSet:
        d = json.loads(raw.decode())
        return cls(
            access_token=d["access_token"],
            expires_at=d.get("expires_at"),
            refresh_token=d.get("refresh_token"),
            scopes=tuple(d.get("scopes") or ()),
            token_type=d.get("token_type") or "Bearer",
        )


@dataclass(frozen=True)
class Account:
    id: str
    provider: str
    external_id: str
    label: str
    client_id: str
    scopes: tuple[str, ...]
    status: str

    def view(self) -> dict:
        """The account for the API and for events (no token, no scopes)."""
        return {
            "id": self.id,
            "label": self.label,
            "provider": self.provider,
            "status": self.status,
        }


AccessTokenFn = Callable[[], str]  # a valid access token; refreshes when necessary


def key_name(account_id: str) -> str:
    return f"{KEY_PREFIX}{account_id}"


def _account(row) -> Account:
    return Account(
        id=row["id"],
        provider=row["provider"],
        external_id=row["external_id"],
        label=row["label"],
        client_id=row["client_id"],
        scopes=tuple(loads(row["scopes"]) or ()),
        status=row["status"],
    )


class CredentialStore:
    def __init__(
        self,
        keystore: Keystore,
        store: IndexStore,
        http: HttpTransport,
        clients: Callable[..., OAuthClient | None],
        clock: Callable[[], float] = time.time,
        publish: Callable[[str, dict], None] | None = None,
    ) -> None:
        self.keystore = keystore
        self.store = store
        self.http = http
        self.clients = clients
        self.clock = clock
        self.publish = publish

    # -------------------------------------------------------------- rows

    def accounts(self) -> list[Account]:
        return [_account(r) for r in self.store.q("SELECT * FROM account ORDER BY created_at, id")]

    def account(self, account_id: str) -> Account | None:
        row = self.store.one("SELECT * FROM account WHERE id = ?", (account_id,))
        return None if row is None else _account(row)

    def _need(self, account_id: str) -> Account:
        acct = self.account(account_id)
        if acct is None:
            raise SourceFault("auth_expired", "the account is not there")
        return acct

    def _event(self, acct: Account) -> None:
        if self.publish is not None:
            self.publish("account.state", acct.view())

    def save(
        self, provider: str, external_id: str, label: str, client_id: str, tokens: TokenSet
    ) -> Account:
        """Store a grant. The same (provider, client, person) gives the same
        account: the scopes join, the status is `ok`, the token is new."""
        if provider not in PROVIDERS and provider not in API_KEY_PROVIDERS:
            raise ValueError(f"unknown provider: {provider}")
        now = format_time(datetime.fromtimestamp(int(self.clock()), UTC))
        with self.store.transaction():
            row = self.store.one(
                "SELECT * FROM account WHERE provider = ? AND client_id = ? AND external_id = ?",
                (provider, client_id, external_id),
            )
            if row is None:
                account_id = secrets.token_bytes(16).hex()
                scopes = sorted(set(tokens.scopes))
                self.store.x(
                    "INSERT INTO account (id, provider, external_id, label, client_id, scopes,"
                    " status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'ok', ?)",
                    (account_id, provider, external_id, label, client_id, dumps(scopes), now),
                )
            else:
                account_id = row["id"]
                scopes = sorted(set(loads(row["scopes"]) or ()) | set(tokens.scopes))
                if not tokens.refresh_token:
                    old = self.tokens(account_id)
                    if old is not None and old.refresh_token:
                        tokens = replace(tokens, refresh_token=old.refresh_token)
                self.store.x(
                    "UPDATE account SET label = ?, scopes = ?, status = 'ok' WHERE id = ?",
                    (label, dumps(scopes), account_id),
                )
            # The keystore write is in the transaction: a failed write leaves
            # no account row with no token.
            self.keystore.put(key_name(account_id), tokens.to_bytes(), overwrite=True)
        acct = self._need(account_id)
        self._event(acct)
        return acct

    def mark(self, account_id: str, status: str) -> None:
        if status not in STATUSES:
            raise ValueError(f"unknown account status: {status}")
        self.store.x("UPDATE account SET status = ? WHERE id = ?", (status, account_id))
        acct = self.account(account_id)
        if acct is not None:
            self._event(acct)

    def tokens(self, account_id: str) -> TokenSet | None:
        raw = self.keystore.get(key_name(account_id))
        return None if raw is None else TokenSet.from_bytes(raw)

    # ------------------------------------------------------------ tokens

    def _client(self, acct: Account) -> OAuthClient:
        client = self.clients(acct.provider, acct.client_id)
        if client is None:
            raise SourceFault("client_missing", "the OAuth client of this account is not set")
        return client

    def access_token(self, account_id: str, *, force_refresh: bool = False) -> str:
        acct = self._need(account_id)
        if acct.status != "ok":
            raise SourceFault("auth_expired", "the account needs a new sign-in")
        with _lock(account_id):
            tokens = self.tokens(account_id)
            if tokens is None:
                self.mark(account_id, "expired")
                raise SourceFault("auth_expired", "no token for this account")
            if not force_refresh and not self._expiring(tokens):
                return tokens.access_token
            if acct.provider in API_KEY_PROVIDERS or not tokens.refresh_token:
                if force_refresh or self._expiring(tokens):
                    self.mark(account_id, "expired")
                    raise SourceFault("auth_expired", "the token cannot be refreshed")
                return tokens.access_token
            return self._refresh(acct, tokens).access_token

    def _expiring(self, tokens: TokenSet) -> bool:
        return tokens.expires_at is not None and tokens.expires_at - self.clock() < REFRESH_BEFORE_S

    def _refresh(self, acct: Account, tokens: TokenSet) -> TokenSet:
        provider = PROVIDERS[acct.provider]
        client = self._client(acct)
        headers, body = token_request(
            provider,
            client,
            {"grant_type": "refresh_token", "refresh_token": tokens.refresh_token or ""},
        )
        resp = self.http("POST", provider.token_url, headers, body)
        if resp.status == 200:
            new = parse_tokens(resp.json(), self.clock(), old=tokens)
            self.keystore.put(key_name(acct.id), new.to_bytes(), overwrite=True)
            return new
        if resp.status in (400, 401) and token_error(resp) in (
            "invalid_grant",
            "unauthorized_client",
            "invalid_client",
        ):
            # Another process can have refreshed with a rotated token.
            again = self.tokens(acct.id)
            if (
                again is not None
                and again.refresh_token != tokens.refresh_token
                and not self._expiring(again)
            ):
                return again
            self.mark(acct.id, "expired")
            raise SourceFault(
                "auth_expired", "the provider refused the refresh", status=resp.status
            )
        kind = classify_status(resp)
        code = {"retry": "rate_limited" if resp.status == 429 else "offline"}.get(kind, "unknown")
        raise SourceFault(code, f"token refresh gave HTTP {resp.status}", status=resp.status)

    # ------------------------------------------------------------- calls

    def _check_host(self, acct: Account, url: str) -> None:
        provider = PROVIDERS.get(acct.provider)
        hosts = provider.api_hosts if provider is not None else API_KEY_HOSTS.get(acct.provider, ())
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in hosts:
            raise SourceFault("unknown", "a token request to a host that is not permitted")

    def auth_headers(
        self, account_id: str, url: str, *, force_refresh: bool = False
    ) -> dict[str, str]:
        """The `Authorization` header for a call to `url`. A host that is not
        an API host of the provider is refused."""
        acct = self._need(account_id)
        self._check_host(acct, url)
        token = self.access_token(account_id, force_refresh=force_refresh)
        return {"Authorization": f"Bearer {token}"}

    def request(
        self,
        account_id: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        **backoff,
    ) -> HttpResponse:
        """One API call with the token of the account (`call_with_backoff`).
        A 401 refreshes the token one time and calls again. A second 401
        marks the account `expired`."""
        hdrs = {**(headers or {}), **self.auth_headers(account_id, url)}
        backoff.setdefault("clock", self.clock)  # `retry_at` in the time of the index
        try:
            return call_with_backoff(
                self.http,
                method,
                url,
                hdrs,
                body,
                reauth=lambda: self.auth_headers(account_id, url, force_refresh=True),
                **backoff,
            )
        except SourceFault as exc:
            if exc.code == "auth_expired":
                acct = self.account(account_id)
                if acct is not None and acct.status == "ok":
                    self.mark(account_id, "expired")
            raise

    # ------------------------------------------------------------ remove

    def delete(self, account_id: str) -> None:
        """Delete the token and the account row, with no provider call."""
        self.keystore.delete(key_name(account_id))
        self.store.x("DELETE FROM account WHERE id = ?", (account_id,))

    def revoke(self, account_id: str) -> bool:
        """The provider revoke call, then the local delete. True if the
        provider confirmed. If the call fails (offline), the token is
        deleted here in each case and the person removes the access at the
        provider page."""
        acct = self.account(account_id)
        if acct is None:
            return False
        tokens = self.tokens(account_id)
        confirmed = False
        provider = PROVIDERS.get(acct.provider)
        if tokens is not None and provider is not None:
            try:
                client = self.clients(acct.provider, acct.client_id)
                confirmed = provider_revoke(provider, client, tokens, self.http)
            except Exception as exc:  # the local delete runs in each case
                log.warning("token revoke failed: %s", type(exc).__name__)
        self.delete(account_id)
        if self.publish is not None:
            self.publish("account.state", {**acct.view(), "status": "revoked"})
        return confirmed
