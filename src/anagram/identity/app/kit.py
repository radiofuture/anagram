"""The recovery kit of the device (layer L1): the kit text, the kit file,
and the restore of the device keys from the encrypted backup on the node."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from anagram.core.errors import ClientError, FormatError
from anagram.core.nodeapi import HttpNode, NodeHTTPError, Transport
from anagram.identity.app.device import write_config
from anagram.identity.app.identity import (
    Home,
    OpenHome,
    config_from_trust,
    device_sign_in,
    fetch_trust,
)
from anagram.identity.app.keychain import open_keystore
from anagram.identity.app.session import write_session
from anagram.identity.formats.backup import backup_id as derive_backup_id
from anagram.identity.formats.backup import decode_secret, open_backup
from anagram.identity.formats.documents import validate_subject

KIT_FILE = "recovery-kit.md"  # an older home has this plain file; no new one is written


@dataclass(frozen=True)
class RecoveryKit:
    text: str  # the printable kit
    code: str  # the recovery code in it


def kit_file_path(home: str | Path, path: str | Path) -> Path:
    """The path for a recovery kit file. A path in the data directory is
    refused: the kit must not stay next to the data that it restores."""
    out = Path(path).expanduser().resolve()
    if out.is_relative_to(Path(home).expanduser().resolve()):
        raise ClientError("keep the recovery kit outside the Anagram data directory")
    if out.is_dir():
        raise ClientError("the recovery kit path is a directory; give a file name")
    return out


def write_private(path: Path, text: str) -> None:
    """Write a new file that only the owner can read (mode 0600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def write_kit_file(home: str | Path, path: str | Path, text: str) -> Path:
    """Write a recovery kit to a file outside the data directory (mode 0600)."""
    out = kit_file_path(home, path)
    write_private(out, text)
    return out


_KIT_LINE = re.compile(r"^(node|node key|subject|recovery code): *(.+)$", re.IGNORECASE | re.M)


def parse_kit(text: str) -> dict:
    fields = {m.group(1).lower(): m.group(2).strip() for m in _KIT_LINE.finditer(text)}
    if set(fields) != {"node", "node key", "subject", "recovery code"}:
        raise ClientError("this file is not an Anagram recovery kit")
    return fields


def recover(
    home: str | Path,
    kit_text: str,
    *,
    open_home: OpenHome,
    transport: Transport | None = None,
    clock: Callable[[], float] | None = None,
) -> Home:
    """Restore device keys from the encrypted backup on the node."""

    home = Path(home)
    if (home / "config.json").exists():
        raise ClientError(f"{home} already has Anagram data; use an empty --home")
    kit = parse_kit(kit_text)
    try:
        secret = decode_secret(kit["recovery code"])
        subject = validate_subject(kit["subject"])
    except FormatError as exc:
        raise ClientError(str(exc)) from exc
    node = HttpNode(kit["node"], transport)
    trust = fetch_trust(node, kit["node key"])
    try:
        doc = node.call("GET", f"/recovery/backup/{derive_backup_id(secret)}")
        keys = open_backup(secret, doc)
    except NodeHTTPError as exc:
        raise ClientError("the node has no backup for this recovery code") from exc
    except FormatError as exc:
        raise ClientError(str(exc)) from exc
    if doc["subject"] != subject:
        raise ClientError("backup is for another person")
    return restore_keys(
        home, node, trust, kit["node key"], subject, keys, open_home=open_home, clock=clock
    )


def restore_keys(
    home: Path,
    node: HttpNode,
    trust: dict,
    node_key: str,
    subject: str,
    keys: dict[str, bytes],
    *,
    open_home: OpenHome,
    clock: Callable[[], float] | None = None,
) -> Home:
    """Write restored keys and the config, then check that the restored device
    key is still active in the key directory."""
    home.mkdir(parents=True, exist_ok=True)
    ks = open_keystore(home)
    for name, value in keys.items():
        ks.put(name, value)
    cfg = config_from_trust(trust, node_key, subject)
    write_config(home, cfg)
    client = open_home(home, node, clock)
    state = client.directory.lookup(subject)
    if client.device.my_device()["ed25519"] not in state.devices:
        raise ClientError("the restored device key is no longer active in the key directory")
    cfg["identity"]["orcid_commitment"] = state.orcid_commitment
    client.device.save_config(cfg)
    for d in state.devices.values():
        client.device.vault.expect_device(d)
    client.directory.monitor()
    # A session from the restored device key, then the personal store.
    session = device_sign_in(node, subject, client.device.device_key(), node_key)
    write_session(ks, session)
    node.token = session["token"]
    client.personal.restore_personal_store()
    return client
