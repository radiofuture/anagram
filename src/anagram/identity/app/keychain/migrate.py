"""Move the hex key files of a home into the sealed keystore.

Keep it while the `file` policy writes hex key files: a home that moves
from `file` to the keychain uses it too, not only an old home.

Order (each step is safe after a stop of the process):

1. Record the new keystore ID in `<home>/keys/.migrate.json`. Make the master
   key and put it in the slot.
2. For each `<name>.key` and `<name>.key.replaced-<n>`: write the sealed file,
   read it back, and compare.
3. Write the marker atomically. This is the commit point. Before it, the hex
   files are the truth; the next try removes the sealed files and the master
   key of the stopped try.
4. Write zeros on each hex file, fsync, unlink. If the process stops here,
   `open_keystore` erases the remaining hex files.

The erase is best effort on an SSD. The caller must make sure that no other
process uses the home during the migration (the app service holds the app
lock).
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
from pathlib import Path

from anagram.identity.app.keychain import (
    FILE_BACKEND,
    MIGRATION_FILE,
    keys_dir,
    legacy_files,
    new_id,
    policy,
    read_marker,
    sealed_twin,
    slots,
    write_marker,
)
from anagram.identity.app.keychain.sealed import SUFFIX, SealedKeystore
from anagram.identity.app.keychain.slots import MasterSlot
from anagram.identity.app.keystore import KeystoreError, erase_file

_HEX_SUFFIX = ".key"


def needs_migration(home: str | Path) -> bool:
    """True if the keys of this home are hex files and the policy asks for the
    OS keychain: hex files with no marker, or a marker with the backend `file`,
    while the policy is not `file`. This function does not read the keychain."""
    if policy() == "file":
        return False
    marker = read_marker(home)
    if marker is None:
        return bool(legacy_files(home))
    return marker["backend"] == FILE_BACKEND


def _clean_stopped_try(d: Path, slot: MasterSlot) -> None:
    """Remove what a try that stopped before its commit point left."""
    for p in d.iterdir():
        if p.name.endswith(SUFFIX) or f"{SUFFIX}.replaced-" in p.name:
            erase_file(p)
    pending = d / MIGRATION_FILE
    if pending.exists():
        with contextlib.suppress(ValueError, KeyError, TypeError):
            slot.delete(slots.account(json.loads(pending.read_text())["id"]))
        os.unlink(pending)


def migrate_to_os(home: str | Path, slot: MasterSlot) -> dict:
    """Seal the hex key files of a home with a new master key in `slot`.
    Return `{"backend": str, "moved": [names]}`."""
    home = Path(home)
    marker = read_marker(home)
    if marker is not None and marker["backend"] != FILE_BACKEND:
        raise KeystoreError("this home already uses a keychain")
    d = keys_dir(home)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    _clean_stopped_try(d, slot)

    keystore_id = new_id()
    master = secrets.token_bytes(32)
    (d / MIGRATION_FILE).write_text(json.dumps({"id": keystore_id}) + "\n")
    slot.set(slots.account(keystore_id), master)

    sealed = SealedKeystore(d, master, keystore_id)
    moved: list[str] = []
    hex_files = legacy_files(home)
    for p in hex_files:
        text = p.read_text(encoding="ascii", errors="replace").strip()
        try:
            secret = bytes.fromhex(text)
        except ValueError:
            secret = b""
        if not secret:
            raise KeystoreError(f"key file {p.name} is empty or malformed; nothing was changed")
        if p.name.endswith(_HEX_SUFFIX):
            name = p.name[: -len(_HEX_SUFFIX)]
            sealed.put(name, secret)
            moved.append(name)
        else:
            # A copy that `replace` kept: `<name>.key.replaced-<n>`.
            name = p.name.split(_HEX_SUFFIX, 1)[0]
            sealed.write_file(name, secret, sealed_twin(p))
        if sealed.read_file(name, sealed_twin(p)) != secret:
            raise KeystoreError(f"sealed copy of {p.name} does not agree; nothing was changed")
    sealed.fsync_dir()

    write_marker(home, slot.backend, keystore_id, overwrite=True)  # the commit point
    for p in hex_files:
        erase_file(p)
    os.unlink(d / MIGRATION_FILE)
    sealed.fsync_dir()
    return {"backend": slot.backend, "moved": sorted(moved)}


__all__ = ["migrate_to_os", "needs_migration"]
