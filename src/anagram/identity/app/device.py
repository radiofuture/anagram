"""The device part of the client (layer L1).

`Device` holds what each client service of this computer uses: the data
directory, the config, the keystore and the device keys, the clock, the local
vault, the connection to the node, and the sealed vault items. It makes no
other service. The composition root (`anagram.shell.client.Client`) makes one
`Device` and gives it to each service as a parameter.

The vault is a port here (`LocalVault`): the vault is layer L2, and the root
gives it.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from cryptography import x509

from anagram.core.crypto import aead
from anagram.core.crypto.hashing import TAG_VAULT_ITEM, lp, tagged_message
from anagram.core.crypto.signing import SigningKey
from anagram.core.crypto.x25519 import X25519Key
from anagram.core.errors import ClientError
from anagram.core.keyvalue import JsonKeys, KeyValue, TextKeys
from anagram.core.nodeapi import HttpNode, NodeAPI
from anagram.identity.app.keystore import Keystore
from anagram.identity.app.session import session_token
from anagram.identity.formats.documents import device_json
from anagram.proofs.anchors.base import AnchorTrust
from anagram.proofs.anchors.defaults import bundled_tsa_roots
from anagram.proofs.log.note import NoteVerifier
from anagram.proofs.proof import Trust

CONFIG_FILE = "config.json"
CONFIG_SCHEMA = "anagram.client_config.v1"
DEVICE_ED25519 = "device-ed25519"
DEVICE_X25519 = "device-x25519"
VAULT_KEY = "vault-key"
INDEX_KEY = "index-key"
# The key of the encrypted local stores of this device (the vault file). It is
# device-local: it is not in the recovery backup and it is not a person key.
LOCAL_STORE_KEY = "local-store-key"
PENDING_KIT = "recovery-kit/pending"  # local vault key of a kit that is not saved yet


class LocalVault(KeyValue, Protocol):
    """The calls of the local vault (L2, `anagram.local.vault.Vault`) that
    layer L1 makes: the log and directory state, the alerts, the sealed
    items, and the key-value table (through `IdentityKeys`). The
    composition root gives the vault. The personal store reads the
    records that it backs up through its own port (`BackupRecords`)."""

    def close(self) -> None: ...

    def log_state(self, origin: str) -> tuple[int, str, str] | None: ...

    def set_log_state(self, origin: str, size: int, root: str, checkpoint: str) -> None: ...

    def expect_device(self, device: dict) -> None: ...

    def expected_devices(self) -> set[str]: ...

    def add_directory_entry(self, leaf_index: int, subject: str, entry: dict) -> None: ...

    def directory_entries(self, subject: str | None = None) -> list[tuple[int, dict]]: ...

    def monitor_state(self, origin: str) -> tuple[int, list[bytes]]: ...

    def set_monitor_state(self, origin: str, size: int, frontier: list[bytes]) -> None: ...

    def add_alert(self, leaf_index: int | None, text: str) -> None: ...

    def sealed_items(self) -> list[tuple[str, str, str, str]]: ...

    def get_sealed(self, kind: str, ref: str) -> tuple[bytes, bytes] | None: ...

    def put_sealed(self, kind: str, ref: str, nonce: bytes, ct: bytes) -> None: ...

    def is_empty(self) -> bool: ...


class IdentityKeys:
    """The L1 keys of the vault key-value table (the keys and the stored
    text did not change)."""

    def __init__(self, kv: KeyValue) -> None:
        self.pending_kit = TextKeys(kv, PENDING_KIT)  # a recovery kit that is not saved yet
        self.monitor_cursor = TextKeys(kv, "monitor_alerts:")  # log origin -> entries checked
        self.store_records = TextKeys(kv, "store/rec/")  # record ID -> "<version> <digest>"
        self.store_skip = TextKeys(kv, "store/skip/")  # record ID -> version not to fetch
        self.store_snapshots = JsonKeys(kv, "store/snap/")  # ref -> {"at", "sha256", "version"}
        self.store_last_sync = TextKeys(kv, "store/last_sync")
        self.store_last_error = TextKeys(kv, "store/last_error")


def read_config(home: str | Path) -> dict:
    path = Path(home) / CONFIG_FILE
    if not path.exists():
        raise ClientError(f"no Anagram data in {home}; run `anagram init`")
    return json.loads(path.read_text())


def write_config(home: str | Path, cfg: dict) -> None:
    (Path(home) / CONFIG_FILE).write_text(json.dumps(cfg, indent=2) + "\n")


def trust_from_config(cfg: dict) -> Trust:
    """Pinned trust from a client config. The TSA roots of the default TSAs
    (`anagram.proofs.anchors.defaults`) are added unless "bundled_tsa_roots" is false."""
    t = cfg["trust"]
    bundled = bundled_tsa_roots() if t.get("bundled_tsa_roots", True) else []
    return Trust(
        log_keys=[NoteVerifier.parse(v) for v in t["log_keys"]],
        witness_keys=[NoteVerifier.parse(v) for v in t.get("witness_keys", [])],
        witness_threshold=t.get("witness_threshold"),
        anchors=AnchorTrust(
            fake_keys=[bytes.fromhex(k) for k in t.get("fake_anchor_keys", [])],
            tsa_roots=[x509.load_pem_x509_certificate(p.encode()) for p in t.get("tsa_roots", [])]
            + bundled,
            bitcoin_headers={
                int(h): (bytes.fromhex(v[0]), int(v[1]))
                for h, v in t.get("bitcoin_headers", {}).items()
            },
        ),
        min_anchors=t.get("min_anchors", 1),
    )


def _item_aad(kind: str, ref: str) -> bytes:
    return tagged_message(TAG_VAULT_ITEM, lp(kind.encode()) + ref.encode())


class Device:
    """The data directory, keys, config, clock, vault, and node connection of
    this computer. `local_node` opens the in-process node of a home in
    "local" mode (the composition root gives it)."""

    def __init__(
        self,
        home: str | Path,
        keystore: Keystore,
        vault: LocalVault,
        *,
        clock: Callable[[], float] = time.time,
        node: NodeAPI | None = None,
        local_node: Callable[[], NodeAPI] | None = None,
    ) -> None:
        self.home = Path(home)
        self.config = read_config(self.home)
        self.keystore = keystore
        self.vault = vault
        self.keys = IdentityKeys(vault)
        self.clock = clock
        self._node = node
        self._local_node = local_node

    # ----------------------------------------------------------- config

    def save_config(self, cfg: dict | None = None) -> None:
        """Write the config (`cfg`, or the current one) and use it."""
        if cfg is not None:
            self.config = cfg
        write_config(self.home, self.config)

    def identity_config(self) -> dict:
        return self.config["identity"]

    @property
    def subject(self) -> str:
        s = self.config.get("identity", {}).get("subject")
        if not s:
            raise ClientError("not joined to a community; run `anagram join INVITE_URL`")
        return s

    def trust(self) -> Trust:
        return trust_from_config(self.config)

    def now(self) -> datetime:
        return datetime.fromtimestamp(int(self.clock()), UTC)

    # ------------------------------------------------------------- node

    @property
    def node(self) -> NodeAPI:
        if self._node is None:
            ncfg = self.config["node"]
            if ncfg["mode"] == "local":
                if self._local_node is None:
                    raise ClientError("this home has a local node, but no way to open it")
                self._node = self._local_node()
            else:
                self._node = HttpNode(ncfg["url"], token=self.session_token())
        return self._node

    @node.setter
    def node(self, node: NodeAPI) -> None:
        self._node = node

    @property
    def http(self) -> HttpNode:
        node = self.node
        if not isinstance(node, HttpNode):
            raise ClientError("this needs a community node; run `anagram join INVITE_URL`")
        return node

    def session_token(self) -> str | None:
        return session_token(self.keystore)

    # ------------------------------------------------------------- keys

    def device_key(self) -> SigningKey:
        seed = self.keystore.get(DEVICE_ED25519)
        if seed is None:
            raise ClientError("device key missing")
        return SigningKey.from_seed(seed)

    def x25519_key(self) -> X25519Key:
        raw = self.keystore.get(DEVICE_X25519)
        if raw is None:
            raise ClientError("device X25519 key missing")
        return X25519Key.from_private_bytes(raw)

    def my_device(self) -> dict:
        return device_json(self.device_key().public_bytes(), self.x25519_key().public_bytes())

    def vault_key(self) -> bytes:
        key = self.keystore.get(VAULT_KEY)
        if key is None:
            raise ClientError("vault key missing")
        return key

    def index_key(self) -> bytes:
        """The person's index key (made on first use)."""
        return self.keystore.get_or_create(INDEX_KEY, aead.new_key)

    # ----------------------------------------------------- sealed items

    def seal(self, kind: str, ref: str, data: bytes) -> None:
        """Keep `data` in the vault, sealed with the vault key (a person key,
        so the personal store carries it to each device as ciphertext)."""
        nonce, ct = aead.seal(self.vault_key(), data, _item_aad(kind, ref))
        self.vault.put_sealed(kind, ref, nonce, ct)

    def unseal(self, kind: str, ref: str) -> bytes | None:
        got = self.vault.get_sealed(kind, ref)
        if got is None:
            return None
        return aead.open_sealed(self.vault_key(), got[0], got[1], _item_aad(kind, ref))
