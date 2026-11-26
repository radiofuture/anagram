"""Connected accounts in the local UI (layer L2; the part
`UIService.connections`). The routes are in `shell/ui/routers/sources.py`.

    connections.connect({"kind": "gdrive"})    # start a sign-in; a worker waits
    connections.flow(fid)                       # the state of the sign-in
    connections.connect_key({"kind": "zotero_web", "key": ...})

Rules:

- A sign-in flow holds no token. A token or a key goes only into the
  keystore (`CredentialStore`); no answer and no event holds one.
- The redirect goes to a one-use listener on 127.0.0.1
  (`local/sources/oauth.py`), not to a route of the UI server.
- Events go to `source_state.publisher(store)` (the table `source_event`),
  as in `sources.py`.
"""

from __future__ import annotations

import logging
import secrets
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from anagram.local.api import (
    FLOW_TIMEOUT_S,
    KIND_SCOPES,
    PROVIDERS,
    ConnectorError,
    OAuthError,
    OAuthFlow,
    TokenSet,
    check_zotero_key,
    remove_source,
    source_state,
    zotero_transport,
)
from anagram.shell.ui.source_kinds import FAULT_TEXT, FLOW_TEXT, credentials, error, kind_info

if TYPE_CHECKING:
    from anagram.local.api import LocalIndex, remove_source, source_state
    from anagram.shell.ui.service import UIService

log = logging.getLogger("anagram.shell.ui")

FLOW_KEEP_S = 15 * 60.0  # a finished flow stays readable for this time
API_KEY_CLIENT = "api-key"  # the `client_id` of an account with a pasted key
PROVIDER_PAGES = {
    "google": "https://myaccount.google.com/permissions",
    "notion": "https://www.notion.so/my-integrations",
}


@dataclass
class SignIn:
    """One sign-in flow of the UI. It holds no token."""

    id: str
    kind: str
    provider: str
    flow: OAuthFlow
    started: float
    account_id: str | None = None  # sign in again to this account
    state: str = "waiting"  # waiting | done | denied | expired | error
    account: dict | None = None
    error: str | None = None
    done: threading.Event = field(default_factory=threading.Event)

    def view(self) -> dict:
        out: dict = {"state": self.state}
        if self.account is not None:
            out["account"] = self.account
        if self.error is not None:
            out["error"] = self.error
        return out


def account_sources(idx: LocalIndex, account_id: str) -> list[str]:
    """The sources that use one account, with no source in removal."""
    rows = idx.store.q(
        "SELECT source_id FROM source_state WHERE account_id = ? AND status != ?"
        " ORDER BY source_id",
        (account_id, source_state.REMOVING),
    )
    return [r["source_id"] for r in rows]


class ConnectionsUI:
    def __init__(self, ui: UIService) -> None:
        self.ui = ui
        self._flows: dict[str, SignIn] = {}
        self._flows_lock = threading.Lock()
        # Opens the authorize URL in the system browser. Tests replace it.
        self.open_browser: Callable[[str], object] = webbrowser.open

    def _publish(self, idx: LocalIndex):
        return source_state.publisher(idx.store, self.ui.clock)

    def accounts(self) -> dict:
        out = []
        with self.ui.session(index=True) as (_, idx):
            for acct in credentials(idx).accounts():
                out.append({**acct.view(), "sources": account_sources(idx, acct.id)})
        return {"accounts": out}

    def _sweep_flows(self) -> None:
        now = self.ui.clock()
        with self._flows_lock:
            old = [f for f, s in self._flows.items() if now - s.started > FLOW_KEEP_S]
            gone = [self._flows.pop(f) for f in old]
        for sign_in in gone:
            sign_in.flow.cancel()

    def connect_key(self, body: dict) -> dict:
        """Store a pasted API key: `{"kind": "zotero_web", "key"}`. The key is
        checked at the provider first (`GET /keys/current`); it goes only
        into the keystore."""

        info = kind_info(body.get("kind"))
        if info.auth != "api_key":
            raise error(400, "unknown_kind", "Unknown source type.")
        key = body.get("key")
        with self.ui.session(index=True) as (_, idx):
            transport = idx.transport or zotero_transport()
            try:
                who = check_zotero_key(key.strip() if isinstance(key, str) else key, transport)
            except ConnectorError as exc:
                if str(exc) == "bad_key":
                    raise error(400, "bad_key", "This key does not work.") from None
                raise error(502, "unknown", FAULT_TEXT["unknown"]) from None
            except OSError:
                raise error(503, "offline", FAULT_TEXT["offline"]) from None
            label = who["username"] or f"Zotero {who['user_id']}"
            acct = credentials(idx).save(
                info.provider or "zotero",
                who["user_id"],
                label,
                API_KEY_CLIENT,
                TokenSet(key.strip(), None, None, ()),
            )
            return {"account": acct.view()}

    def connect(self, body: dict) -> dict:
        """Start a sign-in for `{"kind", "account"?}`. With `account`, sign
        in again to that account, or add the scopes of a new kind to it."""
        kind = body.get("kind")
        if not isinstance(kind, str) or kind not in KIND_SCOPES:
            raise error(400, "unknown_kind", "Unknown source type.")
        provider_name, kind_scopes = KIND_SCOPES[kind]
        provider = PROVIDERS[provider_name]
        self._sweep_flows()
        with self.ui.session(index=True) as (_, idx):
            creds = credentials(idx)
            account_id = body.get("account")
            scopes = set(kind_scopes)
            hint = None
            if account_id is not None:
                acct = creds.account(account_id) if isinstance(account_id, str) else None
                if acct is None or acct.provider != provider_name:
                    raise error(404, "no_account", "This account is not there.")
                client = creds.clients(provider_name, acct.client_id)
                scopes |= set(acct.scopes)
                hint = acct.label
            else:
                client = creds.clients(provider_name)
            if client is None:
                raise error(409, "client_missing", FAULT_TEXT["client_missing"])
            flow = OAuthFlow(
                provider,
                client,
                sorted(scopes),
                idx.http,
                login_hint=hint,
                clock=self.ui.clock,
            )
            try:
                url = flow.start()
            except OAuthError:
                raise error(
                    503, "no_port", "Anagram could not start the sign-in. Try again."
                ) from None
            fid = secrets.token_hex(16)
            sign_in = SignIn(fid, kind, provider_name, flow, self.ui.clock(), account_id=account_id)
            with self._flows_lock:
                self._flows[fid] = sign_in
            self._publish(idx)("oauth.flow", {"flow": fid, "state": "waiting"})
        threading.Thread(target=self._finish, args=(sign_in,), daemon=True).start()
        try:
            self.open_browser(url)
        except Exception as exc:  # the page shows the same link
            log.warning("the system browser did not open: %s", type(exc).__name__)
        return {"expires_in": int(FLOW_TIMEOUT_S), "flow": fid, "url": url}

    def _finish(self, sign_in: SignIn) -> None:
        """Wait for the redirect, then store the grant. Runs in its own
        thread for at most `FLOW_TIMEOUT_S`; it holds no lock while it waits."""
        state, error, account = "error", FLOW_TEXT["error"], None
        try:
            tokens, ident = sign_in.flow.finish()
            with self.ui.open_client(index=True) as (_, idx):
                creds = credentials(idx)
                if sign_in.account_id is not None:
                    old = creds.account(sign_in.account_id)
                    if old is None or old.external_id != ident["external_id"]:
                        label = old.label if old is not None else "the same account"
                        raise OAuthError("other_account", label)
                acct = creds.save(
                    sign_in.provider,
                    ident["external_id"],
                    ident["label"],
                    sign_in.flow.client.client_id,
                    tokens,
                )
                now = self.ui.clock()
                publish = self._publish(idx)
                for sid in account_sources(idx, acct.id):
                    st = source_state.get(idx.store, sid, now)
                    if st.error_code in ("auth_expired", "client_missing", "permission_lost"):
                        source_state.clear_fault(idx.store, sid, now=now, publish=publish)
                    if sign_in.provider == "notion":
                        # "Choose pages" at Notion can add old pages and
                        # remove pages: read the selection again.
                        source_state.set_cursor(idx.store, sid, {"reset": True}, now=now)
            state, error, account = "done", None, acct.view()
        except OAuthError as exc:
            if exc.code == "other_account":
                error = FLOW_TEXT["other_account"].format(label=exc.detail)
            elif exc.code in ("denied", "expired"):
                state, error = exc.code, FLOW_TEXT[exc.code]
            elif exc.code == "cancelled":
                state, error = "expired", FLOW_TEXT["cancelled"]
            elif exc.code == "scope_missing":
                state, error = "denied", FLOW_TEXT["scope_missing"]
        except Exception as exc:  # the page shows the state
            log.warning("sign-in failed: %s", type(exc).__name__)
        sign_in.state, sign_in.error, sign_in.account = state, error, account
        try:
            with self.ui.open_client(index=True) as (_, idx):
                self._publish(idx)("oauth.flow", {"flow": sign_in.id, "state": state})
        except Exception as exc:  # the page also reads the flow
            log.warning("sign-in event failed: %s", type(exc).__name__)
        sign_in.done.set()

    def _flow(self, fid: str) -> SignIn:
        with self._flows_lock:
            sign_in = self._flows.get(fid) if isinstance(fid, str) else None
        if sign_in is None:
            raise error(404, "no_flow", "This sign-in is not there. Start again.")
        return sign_in

    def flow(self, fid: str) -> dict:
        return self._flow(fid).view()

    def cancel(self, fid: str) -> dict:
        self._flow(fid).flow.cancel()
        return {}

    def remove_account(self, account_id: str, *, remove_sources: bool = False) -> dict:
        """Disconnect an account: remove its sources (if asked), revoke the
        grant at the provider, and delete the token. If the provider did not
        confirm the revoke, `provider_page` is where the person removes the
        access."""
        if not isinstance(remove_sources, bool):
            raise error(400, "bad_value", "This setting is on or off.")
        with self.ui.session(index=True) as (_, idx):
            creds = credentials(idx)
            acct = creds.account(account_id) if isinstance(account_id, str) else None
            if acct is None:
                raise error(404, "no_account", "This account is not there.")
            sids = account_sources(idx, acct.id)
            if sids and not remove_sources:
                raise error(409, "account_in_use", "Sources use this account. Remove them too.")
            publish = self._publish(idx)
            revoked = False
            for sid in sids:
                out = remove_source(idx, sid, publish=publish)
                revoked = revoked or out["account_revoked"]
            if creds.account(acct.id) is not None:
                revoked = creds.revoke(acct.id)
        out = {"removed_sources": len(sids), "revoked": revoked}
        if not revoked:
            out["provider_page"] = PROVIDER_PAGES.get(acct.provider)
        return out
