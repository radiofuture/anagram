"""The local UI service: the composition root of the UI parts, and the
session state that they share. The HTTP layer (`shell/ui/server.py`,
`ui/routers/`) is thin: each route calls one method of one part.

Parts (each one calls the API of one layer of the client):

    join          join, sign-in, sign-out, ORCID link (L4, L1)    shell/ui/join.py
    account       overview, identity, devices, guardians, kit (L1) shell/ui/account.py
    people        member directory and search (L1)               shell/ui/people.py
    sources       sources, refresh, folder picker (L2)           shell/ui/sources.py
    connections   connected accounts and sign-in flows (L2)      shell/ui/connections.py
    lab_sources   the source settings of a lab (L2, L3)          shell/ui/lab_sources.py
    library       proposed findings, findings, proof files (L2)  shell/ui/library.py
    models        model profiles, keys, budget, recipients (L2)  shell/ui/models.py
    understanding items, suggestions (L2)                        shell/ui/understanding.py
    agents        assistant access: grants, proposals (XG)       shell/ui/agents.py
    ask           search, ask, timeline (L2)                     shell/ui/ask.py
    sharing       sharing, rings, inbox, reading (L3)            shell/ui/sharing.py
    labs          labs and the lab space (L3)                    shell/ui/labs.py
    enclave       matching through the network enclave (L3)       shell/ui/enclave.py
    settings      the drafting settings (models)                 shell/ui/settings.py

Rules:

- The UI only calls public client and index methods. It adds
  no cryptography and no protocol of its own.
- One lock serialises all actions. Each action opens the client and the index
  and closes them again (SQLite connections are not shared between threads).
- Plain words for the person. IDs and hashes only in "Details" fields.
- Nothing is committed, shared, or submitted without an explicit action.
- A part publishes its live events with `publish` after the action returns.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.nodeapi import HttpNode, NodeHTTPError, Transport
from anagram.identity.api import (
    Keystore,
    SlotLocked,
    clear_session,
    open_keystore,
    read_session,
    session_token,
)
from anagram.local.api import Drafter, LocalIndex
from anagram.models.embed import Embedder
from anagram.models.ollama_client import OllamaClient
from anagram.network.api import ThirdPartyWarning
from anagram.shell.client import Client
from anagram.shell.ui.account import AccountUI
from anagram.shell.ui.agents import AgentsUI
from anagram.shell.ui.ask import AskUI
from anagram.shell.ui.connections import ConnectionsUI
from anagram.shell.ui.enclave import EnclaveUI
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.events import Publisher
from anagram.shell.ui.institutions import InstitutionLookup, StaticInstitutions
from anagram.shell.ui.join import JoinUI
from anagram.shell.ui.lab_sources import LabSourcesUI
from anagram.shell.ui.labs import LabUI
from anagram.shell.ui.library import LibraryUI
from anagram.shell.ui.models import ModelsUI
from anagram.shell.ui.people import PeopleUI
from anagram.shell.ui.settings import SettingsUI
from anagram.shell.ui.sharing import SharingUI
from anagram.shell.ui.sources import SourcesUI
from anagram.shell.ui.state import UIState
from anagram.shell.ui.understanding import UnderstandingUI


class UIService:
    def __init__(
        self,
        home: str | Path,
        *,
        transport: Transport | None = None,
        clock: Callable[[], float] | None = None,
        institutions: InstitutionLookup | None = None,
        drafters: dict[str, Drafter] | None = None,
        return_to: str = "http://127.0.0.1:9/auth/callback",
        ollama: OllamaClient | None = None,
        embedder: Embedder | None = None,
    ) -> None:
        # `ollama`: the local Ollama client for drafting and the Settings
        # check (None: no detection; tests give a fake transport).
        # `embedder`: the index embedder for the lens draft of the matching lines.
        self.ollama = ollama
        self.embedder = embedder
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.transport = transport
        self.clock = clock or time.time
        self.institutions = institutions or StaticInstitutions([])
        self.drafters = drafters or {}
        self.return_to = return_to
        self._ks: Keystore | None = None
        self.state = UIState(self.home, self.keystore)
        self.lock = threading.RLock()
        self.publish = Publisher()
        self.join = JoinUI(self)
        self.account = AccountUI(self)
        self.people = PeopleUI(self)
        self.sources = SourcesUI(self)
        self.connections = ConnectionsUI(self)
        self.lab_sources = LabSourcesUI(self)
        self.library = LibraryUI(self)
        self.models = ModelsUI(self)
        self.understanding = UnderstandingUI(self)
        self.agents = AgentsUI(self)
        self.ask = AskUI(self)
        self.sharing = SharingUI(self)
        self.labs = LabUI(self)
        self.enclave = EnclaveUI(self)
        self.settings = SettingsUI(self)

    # ------------------------------------------------------------ session

    def has_identity(self) -> bool:
        cfg = self.home / "config.json"
        return cfg.exists() and bool(json.loads(cfg.read_text()).get("identity", {}).get("subject"))

    def keystore(self) -> Keystore:
        """The keystore of this home, opened at the first use. A keychain that
        refuses the access is an error that the person can correct."""
        if self._ks is None:
            try:
                self._ks = open_keystore(self.home)
            except SlotLocked as exc:
                raise UIError(
                    423,
                    "Anagram cannot get its key from the keychain of this computer."
                    " Unlock the keychain, then try again.",
                    {"keychain": True},
                ) from exc
        return self._ks

    def joined(self) -> bool:
        if not self.has_identity():
            return False
        return read_session(self.keystore()) is not None

    def _client(self) -> Client:
        if not self.joined():
            raise UIError(409, "Join a community first.")
        cfg = json.loads((self.home / "config.json").read_text())
        token = session_token(self.keystore())
        node = HttpNode(cfg["node"]["url"], self.transport, token=token)
        return Client(self.home, node=node, clock=self.clock)

    @contextmanager
    def session(self, index: bool = False):
        """Lock, open the client (and the index), and close them after use.
        Map client errors to plain UI errors."""
        with self.lock:
            client = self._client()
            idx = LocalIndex.for_client(client, clock=self.clock) if index else None
            try:
                yield (client, idx) if index else client
            except UIError:
                raise
            except ThirdPartyWarning:
                raise
            except LogMisbehaved as exc:
                raise UIError(
                    409,
                    "The community server gave an answer that does not match its public log."
                    " Anagram stopped to keep your data safe. Tell your community organizer.",
                    {"details": str(exc)},
                ) from exc
            except NodeHTTPError as exc:
                if exc.status == 401:
                    # The node ended the session (expired, or this device was
                    # removed). The Join screen signs in again with ORCID only.
                    clear_session(self.keystore())
                    raise UIError(
                        401, "Your sign-in has ended. Sign in again.", {"signin": True}
                    ) from exc
                raise UIError(502, f"The community server said: {exc.detail}") from exc
            except (ClientError, FormatError, KeyError, ValueError) as exc:
                raise UIError(400, str(exc).strip("'\"")) from exc
            finally:
                if idx is not None:
                    idx.close()
                client.close()

    @contextmanager
    def open_client(self, index: bool = False):
        """Open a client (and the index) for background work: the helper and
        the tasks of `shell/ui/tasks.py`. As `session`, but it does not take the UI
        lock and it does not map errors. The caller has its own connections,
        so a long scan does not stop a UI request."""
        client = self._client()
        idx = None
        try:
            if index:
                idx = LocalIndex.for_client(client, clock=self.clock)
            yield (client, idx) if index else client
        finally:
            if idx is not None:
                idx.close()
            client.close()
