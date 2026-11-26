"""The keystore of a client home.

One master key is in the OS keychain. Each other key is a file in
`<home>/keys`, sealed with the master key (`SealedKeystore`). Where there is no
keychain, or where the policy says so, the keys are plain hex files
(`FileKeystore`).

A marker file `<home>/keys/keystore.json` records the backend of a home. The
policy (environment `ANAGRAM_KEYSTORE`) applies only to a home that has no
marker and no keys:

- `file` (default): hex files. Tests and headless hosts use it.
- `os`: the OS keychain, or an error.
- `auto`: the OS keychain if this computer has one, else hex files. The app
  entry points set it.

A home never changes its backend silently. A locked keychain is an error: no
fallback to files, no new keys.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import tempfile
from pathlib import Path

from anagram.identity.app.keychain import slots
from anagram.identity.app.keychain.sealed import SUFFIX, SealedKeystore
from anagram.identity.app.keychain.slots import (
    KeyringSlot,
    MasterSlot,
    MemorySlot,
    SlotLocked,
    SlotUnavailable,
)
from anagram.identity.app.keystore import FileKeystore, Keystore, KeystoreError, erase_file

__all__ = [
    "MARKER",
    "KeyringSlot",
    "MasterSlot",
    "MemorySlot",
    "SealedKeystore",
    "SlotLocked",
    "SlotUnavailable",
    "describe",
    "destroy_keystore",
    "open_keystore",
    "policy",
]

MARKER = "keystore.json"
MARKER_SCHEMA = "anagram.keystore.v2"
POLICY_ENV = "ANAGRAM_KEYSTORE"
POLICIES = ("file", "auto", "os")
FILE_BACKEND = "file"
KEYS_DIR = "keys"
MIGRATION_FILE = (
    ".migrate.json"  # the ID of a migration in progress (anagram.identity.app.keychain.migrate)
)

# The master key of each keystore that this process opened through the OS
# keychain: a process reads the keychain one time for each keystore.
_masters: dict[str, bytes] = {}


def policy() -> str:
    value = os.environ.get(POLICY_ENV, "file").strip().lower() or "file"
    if value not in POLICIES:
        raise KeystoreError(f"{POLICY_ENV} must be one of: {', '.join(POLICIES)}")
    return value


def keys_dir(home: str | Path) -> Path:
    return Path(home) / KEYS_DIR


def read_marker(home: str | Path) -> dict | None:
    """The marker of a home, or None. A marker that is malformed is an error."""
    p = keys_dir(home) / MARKER
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    try:
        doc = json.loads(text)
        ok = (
            isinstance(doc, dict)
            and doc.get("schema") == MARKER_SCHEMA
            and isinstance(doc.get("backend"), str)
            and isinstance(doc.get("id"), str)
            and len(doc["id"]) == 16
            and int(doc["id"], 16) >= 0
        )
    except ValueError:
        ok = False
    if not ok:
        raise KeystoreError("the keystore marker of this home is malformed")
    return doc


def write_marker(home: str | Path, backend: str, keystore_id: str, *, overwrite: bool) -> bool:
    """Write the marker atomically. With `overwrite=False`, return False if a
    marker is there (a second process made the keystore first)."""
    d = keys_dir(home)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    doc = {"backend": backend, "id": keystore_id, "schema": MARKER_SCHEMA}
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".keystore.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, d / MARKER)
        else:
            try:
                os.link(tmp, d / MARKER)
            except FileExistsError:
                return False
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    return True


def new_id() -> str:
    return secrets.token_hex(8)


def legacy_files(home: str | Path) -> list[Path]:
    """The hex key files of a home: `<name>.key` and `<name>.key.replaced-<n>`."""
    d = keys_dir(home)
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.name.endswith(".key") or ".key.replaced-" in p.name)


def sealed_twin(path: Path) -> Path:
    """The sealed file name for a hex key file."""
    return path.with_name(path.name.replace(".key", SUFFIX, 1))


def _sealed(home: Path, marker: dict, slot: MasterSlot | None) -> SealedKeystore:
    keystore_id = marker["id"]
    master = _masters.get(keystore_id) if slot is None else None
    if master is None:
        use = slot or slots.os_slot()
        if use.backend != marker["backend"]:
            raise KeystoreError(
                f"this home uses the keystore backend {marker['backend']}, not {use.backend}"
            )
        master = use.get(slots.account(keystore_id))
        if master is None:
            # Never make a new master key here: the sealed keys would be lost.
            raise KeystoreError("the master key of this home is not in the keychain")
        if slot is None:
            _masters[keystore_id] = master
    # A migration that stopped after its commit point can leave hex files.
    for p in legacy_files(home):
        if sealed_twin(p).exists():
            erase_file(p)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(keys_dir(home) / MIGRATION_FILE)
    return SealedKeystore(keys_dir(home), master, keystore_id)


def _create_sealed(home: Path, slot: MasterSlot) -> Keystore:
    keystore_id = new_id()
    master = secrets.token_bytes(32)
    slot.set(slots.account(keystore_id), master)
    if not write_marker(home, slot.backend, keystore_id, overwrite=False):
        slot.delete(slots.account(keystore_id))  # a second process was first
        return open_keystore(home, slot=slot)
    return SealedKeystore(keys_dir(home), master, keystore_id)


def _create_file(home: Path) -> Keystore:
    if not write_marker(home, FILE_BACKEND, new_id(), overwrite=False):
        return open_keystore(home)
    return FileKeystore(keys_dir(home))


def open_keystore(home: str | Path, *, slot: MasterSlot | None = None) -> Keystore:
    """Open the keystore of a home (the directory `<home>/keys`).

    Marker present: the recorded backend (`file` gives `FileKeystore`; each
    other backend gives `SealedKeystore`).
    Marker absent, hex key files present: `FileKeystore`. The migration is a
    separate, explicit step (`anagram.identity.app.keychain.migrate`).
    Marker absent, no keys: the policy decides, and the marker is written.

    `slot` replaces the OS keychain (tests). It does not change the policy.
    Raises `SlotLocked` if the keychain refuses the access and
    `SlotUnavailable` if the home needs a keychain that this computer does not
    have."""
    home = Path(home)
    marker = read_marker(home)
    if marker is not None:
        if marker["backend"] == FILE_BACKEND:
            return FileKeystore(keys_dir(home))
        return _sealed(home, marker, slot)
    if legacy_files(home):
        return FileKeystore(keys_dir(home))
    rule = policy()
    if rule == "file":
        return _create_file(home)
    if slot is None:
        try:
            slot = slots.os_slot()
        except SlotUnavailable:
            if rule == "os":
                raise
            return _create_file(home)
    return _create_sealed(home, slot)


def describe(home: str | Path) -> dict:
    """Where the keys of a home are, for the UI: `{"backend", "protected"}`.
    This function does not read the keychain."""
    marker = read_marker(home)
    backend = marker["backend"] if marker else FILE_BACKEND
    return {"backend": backend, "protected": backend != FILE_BACKEND}


def destroy_keystore(home: str | Path, *, slot: MasterSlot | None = None) -> None:
    """Erase each key file of a home and remove its master key from the
    keychain. Only for a keystore of temporary keys (a recovery in progress)."""
    home = Path(home)
    marker = read_marker(home)
    d = keys_dir(home)
    if d.is_dir():
        for p in d.iterdir():
            if p.is_file() and p.name != MARKER:
                erase_file(p)
    if marker is not None and marker["backend"] != FILE_BACKEND:
        _masters.pop(marker["id"], None)
        with contextlib.suppress(SlotUnavailable):
            (slot or slots.os_slot()).delete(slots.account(marker["id"]))
    with contextlib.suppress(FileNotFoundError):
        os.unlink(d / MARKER)
