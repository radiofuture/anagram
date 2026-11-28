"""Client composition root: `Client` makes the device, the log checks, and
each service of the app, and gives each service its parts.

Data directory layout (<home>):

    config.json    node connection and pinned trust (public keys only); after a
                   join also the person ID and the ORCID opening (iD and salt)
    keys/          device-ed25519, device-x25519, vault-key, index-key,
                   local-store-key (anagram.identity.app.keychain: sealed with a master key
                   from the OS keychain, or hex files).
                   vault-key and index-key are person keys: every device of the
                   person has the same ones (spec/identity.md section 12).
                   local-store-key stays on this device
    vault.sqlite   findings, sealed openings, bundles, last seen checkpoint
                   (SQLCipher, key from local-store-key)
    index.sqlite   the local index (anagram.local.index)
    node/          local in-process node (only in "local" mode)

With a community node, the vault records and a snapshot of the index also go to
the personal store on the node, as ciphertext (`anagram.identity.app.personal`).
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from pathlib import Path

from anagram.admission.api import GroupAdmission, GroupInvites
from anagram.core.crypto import aead
from anagram.core.crypto.x25519 import new_private as new_x25519
from anagram.core.devclock import dev_clock_from_env
from anagram.core.errors import ClientError
from anagram.core.nodeapi import LocalNode, NodeAPI
from anagram.identity.api import (
    CONFIG_SCHEMA,
    DEVICE_ED25519,
    DEVICE_X25519,
    LOCAL_STORE_KEY,
    VAULT_KEY,
    Account,
    Device,
    Directory,
    Guardians,
    JoinResult,
    Keystore,
    LogCheck,
    PersonalStore,
    login,
    open_keystore,
    write_config,
)
from anagram.local.api import Findings, LabContext, Vault
from anagram.network.api import (
    SCHEMA as SHARE_TABLES,
)
from anagram.network.api import (
    AppLabs,
    EnclaveMatching,
    Grants,
    LabKeys,
    LabRoster,
    Labs,
    LabSpace,
    LabSpaceConnector,
    ReaderInvites,
    ReadReceipts,
    ReadRecords,
    Received,
    ShareHooks,
    Shares,
    ShareStore,
    ShareSync,
)
from anagram.shell.node.home import DEFAULT_ORIGIN, NodeHome

__all__ = ["Client", "lab_context"]


def lab_context(client: Client | None) -> LabContext | None:
    """The lab context of a session, or None when there is no session."""
    return client.lab_context if client is not None else None


class Client:
    # The composition root of the app gives the ports: the source kinds of L3
    # for the index (`SpaceSource`: the lab space; `LocalIndex.for_client`
    # reads it), and the admission checks
    # of the lab roster (`AdmissionCheck`, `self.admission_check`).
    index_sources: tuple[type, ...] = (LabSpaceConnector,)

    def __init__(
        self,
        home: str | Path,
        node: NodeAPI | None = None,
        keystore: Keystore | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        home = Path(home)
        if not (home / "config.json").exists():
            raise ClientError(f"no Anagram data in {home}; run `anagram init`")
        keystore = keystore or open_keystore(home)
        vault = Vault(
            home / "vault.sqlite",
            keystore.get_or_create(LOCAL_STORE_KEY, aead.new_key),
            tables=(SHARE_TABLES,),  # shares, share_events, reads, fetch_events, received
        )
        self.admission_check = GroupAdmission()  # port `AdmissionCheck` (L4)
        self.device = Device(
            home,
            keystore,
            vault,
            clock=clock,
            node=node,
            local_node=lambda: LocalNode(NodeHome(home / "node").service()),
        )
        self.log = LogCheck(self.device)
        self.directory = Directory(self.device, self.log)
        self.personal = PersonalStore(self.device, self.directory, vault)
        self.account = Account(self.device, self.directory, self.personal)
        self.guardians = Guardians(self.device, self.directory)
        self.findings = Findings(self.device, self.log, self.personal, vault)
        self.lab_roster = LabRoster(self.device, self.directory, self.admission_check)
        self.lab_keys = LabKeys(self.device, self.directory, self.lab_roster)
        self.lab_space = LabSpace(self.device, self.findings, self.lab_roster, self.lab_keys, vault)
        self.labs = Labs(
            self.device,
            self.directory,
            self.account,
            self.lab_roster,
            self.lab_keys,
            self.lab_space,
        )
        # Port `LabContext` of the app, and the parts of the lab space
        # bridge.
        self.lab_context = AppLabs(
            self.device, self.lab_roster, self.lab_keys, self.lab_space, self.labs
        )
        self.admission = GroupInvites(self.device, self.directory, self.lab_roster, self.lab_keys)
        # L3 owns the share tables and the share keys of vault.sqlite.
        self.share_store = ShareStore(vault)
        self.reads = ReadReceipts(self.device, self.share_store)
        self.grants = Grants(
            self.device,
            self.log,
            self.directory,
            self.findings,
            self.lab_roster,
            ShareHooks(self.device, self.reads, self.share_store, vault),
            vault,
        )
        self.shares = Shares(
            self.device,
            self.directory,
            self.findings,
            self.lab_roster,
            self.lab_space,
            self.grants,
            self.share_store,
            vault,
        )
        self.invites = ReaderInvites(self.device, self.grants, self.shares, self.share_store, vault)
        self.read_records = ReadRecords(
            self.device, self.log, self.directory, self.findings, self.share_store, vault
        )
        self.received = Received(self.device, self.grants, self.reads, self.share_store, vault)
        self.share_sync = ShareSync(
            self.device,
            self.grants,
            self.shares,
            self.invites,
            self.read_records,
            self.received,
            self.reads,
            vault,
        )
        # The development clock is used only for a network with development
        # pins (simulated profile); see `EnclaveMatching.now`.
        self.enclave = EnclaveMatching(
            self.device, vault, self.device.clock, dev_clock=dev_clock_from_env()
        )

    # The parts of the device that most callers use.

    @property
    def home(self) -> Path:
        return self.device.home

    @property
    def config(self) -> dict:
        return self.device.config

    @property
    def keystore(self) -> Keystore:
        return self.device.keystore

    @property
    def vault(self) -> Vault:
        return self.device.vault

    @property
    def clock(self) -> Callable[[], float]:
        return self.device.clock

    @property
    def node(self) -> NodeAPI:
        return self.device.node

    @classmethod
    def open(cls, home: Path, node: NodeAPI, clock: Callable[[], float] | None = None) -> Client:
        """Open a home with this node connection: the `OpenHome` port that the
        sign-in functions get (`login`, `recover`, `join`)."""
        return cls(home, node=node, **({"clock": clock} if clock else {}))

    def close(self) -> None:
        self.enclave.close()
        self.device.vault.close()

    def sign_in(self, **kw) -> JoinResult:
        """Sign in again without an invite (see `login`). The keyword arguments
        are those of `login`. This client then uses the new session."""
        http = self.device.http
        kw.setdefault("transport", http.transport)
        kw.setdefault("clock", self.device.clock)
        result = login(self.home, open_home=Client.open, **kw)
        http.token = result.client.device.http.token
        result.client.close()
        result.client = self
        return result

    # ---------------------------------------------------------------- setup

    @classmethod
    def init(
        cls,
        home: str | Path,
        *,
        node_url: str | None = None,
        trust: dict | None = None,
        origin: str = DEFAULT_ORIGIN,
        anchors: list[str] | None = None,
        **kwargs,
    ) -> Client:
        """Create a data directory. Without node_url, also create a local node."""
        home = Path(home)
        home.mkdir(parents=True, exist_ok=True)
        ks = open_keystore(home)
        ks.get_or_create(DEVICE_ED25519, lambda: secrets.token_bytes(32))
        ks.get_or_create(VAULT_KEY, aead.new_key)
        ks.get_or_create(DEVICE_X25519, new_x25519)
        if node_url is None:
            nh = NodeHome(home / "node")
            if not nh.exists():
                nh.create(origin=origin, anchors=anchors)
            node_cfg = {"mode": "local"}
            trust = {**nh.trust_info(), "min_anchors": 1}
        else:
            if not trust or not trust.get("log_keys"):
                raise ClientError("a remote node needs pinned log keys")
            node_cfg = {"mode": "http", "url": node_url}
        write_config(home, {"node": node_cfg, "schema": CONFIG_SCHEMA, "trust": trust})
        return cls(home, **kwargs)
