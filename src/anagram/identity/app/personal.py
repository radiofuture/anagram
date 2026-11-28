"""Personal store, client side (spec/vault.md section 11).

The data that makes proofs work goes with the person, not with one laptop:

- `sync_store()` sends each vault record (sealed openings, bundles, content keys
  and other sealed items, rings, sent grants, the ORCID opening) to the node as
  an `anagram.personal_store.v1` record, sealed with a key from the vault key.
  It also sends a snapshot of each local database in `SNAPSHOT_FILES` (the
  index) in chunks. Local file paths stay on the device.
- `pull_store()` reads new records of the person from the node (records that
  another device of the person sent) into the local vault.
- `restore_personal_store()` (after a recovery): pull, then write the snapshot
  of this device's index if the home has none.
- `send_person_keys()` / `adopt_person_keys()`: the vault key and the index key
  go to a new device of the same person, sealed with HPKE to its X25519 key.

A snapshot is opaque bytes. The client makes it with the SQLite backup API. If
the file is not plain SQLite (for example an encrypted database), the client
copies the file bytes.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Protocol

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke
from anagram.core.errors import ClientError, FormatError, LogMisbehaved
from anagram.core.files import atomic_write
from anagram.core.nodeapi import HttpNode, NodeHTTPError
from anagram.core.timefmt import format_time
from anagram.core.wraps import b64
from anagram.identity.app.device import INDEX_KEY, VAULT_KEY, Device
from anagram.identity.app.directory import Directory
from anagram.identity.formats.documents import check_orcid_opening
from anagram.identity.formats.personal_store import (
    StoreKeys,
    make_person_keys,
    open_person_keys,
    open_record,
    seal_record,
)

KIND_PERSON = "person"
KIND_FINDING = "finding"
KIND_SEALED = "sealed_item"
KIND_RING = "ring"
KIND_GRANT = "grant_sent"
KIND_SNAPSHOT = "snapshot"
KIND_CHUNK = "snapshot_chunk"
VAULT_KINDS = (KIND_PERSON, KIND_FINDING, KIND_SEALED, KIND_RING, KIND_GRANT)

# Snapshot name -> file in the client home. The file is opaque bytes here.
SNAPSHOT_FILES = {"index": "index.sqlite"}
SNAPSHOT_CHUNK = 1 << 20
SNAPSHOT_INTERVAL = 3600  # automatic sync sends a new snapshot at most once an hour


def snapshot_file(path: Path) -> bytes | None:
    """A consistent copy of a database file as bytes, or None if it is absent."""
    if not path.exists():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "snapshot"
        try:
            src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                dst = sqlite3.connect(str(out))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
            return out.read_bytes()
        except sqlite3.DatabaseError:
            return path.read_bytes()  # not plain SQLite: the file bytes as they are


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class BackupRecords(Protocol):
    """The vault records that the personal store backs up and restores
    (the findings of L2, the rings and sent grants of L3). The composition
    root gives the vault."""

    def export_findings(self) -> list[dict]: ...

    def import_finding(self, value: dict) -> None: ...

    def rings(self) -> list[dict]: ...

    def import_ring(self, ring: dict) -> None: ...

    def grants_sent(self, root: str | None = None) -> list[dict]: ...

    def import_grant_sent(self, g: dict) -> None: ...


class PersonalStore:
    """The personal store of this person on the node (layer L1)."""

    def __init__(self, device: Device, directory: Directory, records: BackupRecords) -> None:
        self.device = device
        self.records = records
        self.directory = directory
        self.last_restore: dict | None = None  # the answer of the last restore

    # ------------------------------------------------------------ helpers

    def _store_keys(self) -> StoreKeys:
        return StoreKeys(self.device.vault_key())

    def store_ready(self) -> bool:
        try:
            node = self.device.node
        except (ClientError, OSError, ValueError):
            return False
        return (
            isinstance(node, HttpNode)
            and bool(node.token)
            and bool(self.device.config.get("identity", {}).get("subject"))
        )

    def _device_hex(self) -> str:
        return self.device.device_key().public_bytes().hex()

    def _snapshot_ref(self, name: str) -> str:
        return f"{name}/{self._device_hex()}"

    def personal_records(self) -> list[tuple[str, str, Any]]:
        """All vault records to keep in the personal store: (kind, ref, value)."""
        out: list[tuple[str, str, Any]] = []
        ident = self.device.config.get("identity") or {}
        if ident.get("subject"):
            out.append(
                (
                    KIND_PERSON,
                    "me",
                    {
                        "orcid": ident.get("orcid"),
                        "orcid_commitment": ident.get("orcid_commitment"),
                        # The commitment of a linked iD (not in the key directory)
                        "orcid_link_commitment": ident.get("orcid_link_commitment"),
                        "orcid_salt": ident.get("orcid_salt"),
                        "subject": ident["subject"],
                    },
                )
            )
        for f in self.records.export_findings():
            out.append((KIND_FINDING, f["root"], f))
        for kind, ref, nonce, ct in self.device.vault.sealed_items():
            out.append(
                (KIND_SEALED, f"{kind}|{ref}", {"ct": ct, "kind": kind, "nonce": nonce, "ref": ref})
            )
        for ring in self.records.rings():
            out.append((KIND_RING, ring["name"], ring))
        for g in self.records.grants_sent():
            out.append((KIND_GRANT, g["grant_id"], g))
        return out

    def _listing(self) -> list[dict]:
        return self.device.http.call("GET", "/store/records", auth=True)["records"]

    def _remote(self) -> dict[str, int]:
        return {r["record_id"]: int(r["version"]) for r in self._listing()}

    def _put(self, keys: StoreKeys, kind: str, ref: str, value: Any, version: int) -> int:
        """Send one record. On a version conflict, send a newer version once."""
        rid = keys.record_id(kind, ref)
        for _ in range(2):
            doc = seal_record(keys, kind, ref, value, version)
            try:
                self.device.http.call("PUT", f"/store/records/{rid}", {"record": doc}, auth=True)
                return version
            except NodeHTTPError as exc:
                if exc.status != 409:
                    raise
                version = self._remote().get(rid, version) + 1
        raise ClientError("the node keeps a newer version of a store record; sync again")

    # --------------------------------------------------------------- push

    def sync_store(self, snapshot: bool | str = True) -> dict:
        """Pull new records of my other devices, then send my changed records.
        `snapshot`: True (send changed snapshots), False, or "due" (only if the
        last snapshot is older than SNAPSHOT_INTERVAL)."""
        if not self.store_ready():
            raise ClientError("the personal store needs a community node and a session")
        keys = self._store_keys()
        pulled = self._pull(keys, self._listing())
        remote = self._remote()
        pushed = 0
        for kind, ref, value in self.personal_records():
            rid = keys.record_id(kind, ref)
            digest = _digest(value)
            state = self.device.keys.store_records.get(rid)
            version, last = (int(state.split()[0]), state.split()[1]) if state else (0, "")
            rv = remote.get(rid, 0)
            if last == digest and rv >= version > 0:
                continue  # the node has it (or a newer version from another device)
            v = self._put(keys, kind, ref, value, max(version, rv) + 1)
            self.device.keys.store_records.set(rid, f"{v} {digest}")
            pushed += 1
        snaps = {}
        if snapshot:
            for name in SNAPSHOT_FILES:
                snaps[name] = self._push_snapshot(keys, name, remote, due_only=snapshot == "due")
        now = format_time(self.device.now())
        self.device.keys.store_last_sync.set("", now)
        self.device.keys.store_last_error.delete()
        return {"pulled": pulled, "pushed": pushed, "snapshots": snaps, "synced_at": now}

    def _push_snapshot(self, keys: StoreKeys, name: str, remote: dict, due_only: bool) -> str:
        ref = self._snapshot_ref(name)
        st = self.device.keys.store_snapshots.load(ref) or {}
        if due_only and st.get("at") and self.device.clock() - st["at"] < SNAPSHOT_INTERVAL:
            return "not_due"
        data = snapshot_file(self.device.home / SNAPSHOT_FILES[name])
        if data is None:
            return "absent"
        sha = hashlib.sha256(data).hexdigest()
        mid = keys.record_id(KIND_SNAPSHOT, ref)
        if st.get("sha256") == sha and remote.get(mid) == st.get("version"):
            st["at"] = self.device.clock()
            self.device.keys.store_snapshots.dump(ref, st)
            return "unchanged"
        old = self._remote_manifest(keys, mid) if mid in remote else None
        gen = secrets.token_hex(8)
        chunks = [data[i : i + SNAPSHOT_CHUNK] for i in range(0, len(data), SNAPSHOT_CHUNK)]
        for i, chunk in enumerate(chunks or [b""]):
            self._put(keys, KIND_CHUNK, f"{ref}|{gen}|{i}", {"data": b64(chunk)}, 1)
            self.device.keys.store_skip.set(keys.record_id(KIND_CHUNK, f"{ref}|{gen}|{i}"), "1")
        manifest = {
            "chunks": max(1, len(chunks)),
            "generation": gen,
            "made_at": format_time(self.device.now()),
            "name": name,
            "sha256": sha,
            "size": len(data),
        }
        version = self._put(keys, KIND_SNAPSHOT, ref, manifest, remote.get(mid, 0) + 1)
        self.device.keys.store_skip.set(mid, str(version))
        if old is not None:  # the chunks of the old snapshot are not needed now
            for i in range(int(old["chunks"])):
                rid = keys.record_id(KIND_CHUNK, f"{ref}|{old['generation']}|{i}")
                try:
                    self.device.http.call("DELETE", f"/store/records/{rid}", auth=True)
                except NodeHTTPError as exc:
                    if exc.status != 404:
                        raise
        st = {"at": self.device.clock(), "sha256": sha, "version": version}
        self.device.keys.store_snapshots.dump(ref, st)
        return "sent"

    def _fetch(self, keys: StoreKeys, rid: str) -> tuple[str, str, Any, int] | None:
        doc = self.device.http.call("GET", f"/store/records/{rid}", auth=True)["record"]
        if doc.get("record_id") != rid:
            raise LogMisbehaved("node gave a store record with another ID")
        try:
            kind, ref, value = open_record(keys, doc)
        except FormatError:
            return None  # sealed with another vault key (for example before a reset)
        return kind, ref, value, int(doc["version"])

    def _remote_manifest(self, keys: StoreKeys, mid: str) -> dict | None:
        try:
            got = self._fetch(keys, mid)
        except NodeHTTPError:
            return None
        return got[2] if got and got[0] == KIND_SNAPSHOT else None

    def auto_sync(self) -> None:
        """Best-effort sync after a change (a commit). A failure never stops the
        change; the next sync sends the records."""
        if self.device.config.get("store", {}).get("auto") is False or not self.store_ready():
            return
        try:
            self.sync_store(snapshot="due")
        except (ClientError, NodeHTTPError, OSError, FormatError) as exc:
            self.device.keys.store_last_error.set("", str(exc)[:500])

    # --------------------------------------------------------------- pull

    def _pull(self, keys: StoreKeys, listing: list[dict]) -> int:
        """Import vault records that are newer on the node than here. Non-vault
        records (snapshot manifests and chunks) are recorded in `store_skip`
        after decryption so they are not fetched again."""
        n = 0
        for item in sorted(listing, key=lambda r: r["record_id"]):
            rid, version = item["record_id"], int(item["version"])
            state = self.device.keys.store_records.get(rid)
            if state and int(state.split()[0]) >= version:
                continue
            if self.device.keys.store_skip.get(rid) == str(version):
                continue  # a chunk, a snapshot, or a record of another key
            got = self._fetch(keys, rid)
            if got is None or got[0] not in VAULT_KINDS:
                self.device.keys.store_skip.set(rid, str(version))
                continue
            kind, ref, value, version = got
            self._import(kind, value)
            self.device.keys.store_records.set(rid, f"{version} {_digest(value)}")
            n += 1
        return n

    def _import(self, kind: str, value: Any) -> None:
        if kind == KIND_PERSON:
            self._import_person(value)
        elif kind == KIND_FINDING:
            self.records.import_finding(value)
        elif kind == KIND_SEALED:
            self.device.vault.put_sealed(
                value["kind"],
                value["ref"],
                bytes.fromhex(value["nonce"]),
                bytes.fromhex(value["ct"]),
            )
        elif kind == KIND_RING:
            self.records.import_ring(value)
        elif kind == KIND_GRANT:
            self.records.import_grant_sent(value)

    def _import_person(self, value: dict) -> None:
        ident = self.device.config.setdefault("identity", {})
        if value.get("subject") != ident.get("subject"):
            raise ClientError("the personal store is for another person")
        commitment = ident.get("orcid_commitment") or value.get("orcid_commitment")
        link = None if commitment else value.get("orcid_link_commitment")
        if value.get("orcid"):
            salt = bytes.fromhex(value.get("orcid_salt") or "")
            if not check_orcid_opening(commitment or link or "", value["orcid"], salt):
                raise ClientError("the ORCID opening in the personal store does not match")
            if not ident.get("orcid"):
                ident.update(
                    {"orcid": value["orcid"], "orcid_salt": value["orcid_salt"]}
                    | ({"orcid_commitment": commitment} if commitment else {})
                    | ({"orcid_link_commitment": link} if link else {})
                )
                self.device.save_config()

    def pull_store(self) -> int:
        if not self.store_ready():
            raise ClientError("the personal store needs a community node and a session")
        keys = self._store_keys()
        return self._pull(keys, self._listing())

    def restore_personal_store(self) -> dict:
        """After a recovery: read all records into the vault, and write the
        snapshot of this device's index if the home has no index yet."""
        try:
            keys = self._store_keys()
            listing = self._listing()
        except NodeHTTPError as exc:
            if exc.status == 404:
                self.last_restore = {"status": "no_store"}
                return self.last_restore
            raise
        remote = {r["record_id"]: int(r["version"]) for r in listing}
        pulled = self._pull(keys, listing)
        snaps = {}
        for name, fname in SNAPSHOT_FILES.items():
            snaps[name] = self._restore_snapshot(keys, name, self.device.home / fname, remote)
        self.last_restore = {"pulled": pulled, "snapshots": snaps, "status": "restored"}
        return self.last_restore

    def _restore_snapshot(self, keys: StoreKeys, name: str, path: Path, remote: dict) -> str:
        ref = self._snapshot_ref(name)
        mid = keys.record_id(KIND_SNAPSHOT, ref)
        if mid not in remote:
            return "none"
        manifest = self._remote_manifest(keys, mid)
        if manifest is None:
            return "unreadable"
        parts = []
        for i in range(int(manifest["chunks"])):
            rid = keys.record_id(KIND_CHUNK, f"{ref}|{manifest['generation']}|{i}")
            got = self._fetch(keys, rid) if rid in remote else None
            if got is None or got[0] != KIND_CHUNK:
                raise ClientError(f"snapshot {name} is not complete on the node")
            parts.append(base64.b64decode(got[2]["data"]))
        data = b"".join(parts)
        if hashlib.sha256(data).hexdigest() != manifest["sha256"] or len(data) != manifest["size"]:
            raise ClientError(f"snapshot {name} does not match its manifest")
        target = path if not path.exists() else path.with_name(path.name + ".restored")
        atomic_write(target, data, mode=0o600)
        st = {"at": self.device.clock(), "sha256": manifest["sha256"], "version": remote[mid]}
        self.device.keys.store_snapshots.dump(ref, st)
        return "restored" if target == path else f"restored to {target.name}"

    # -------------------------------------------------------- person keys

    def send_person_keys(self, device: dict) -> dict:
        """Give the person keys to another active device of mine (HPKE)."""
        package = make_person_keys(
            subject=self.device.subject,
            recipient=device,
            keys={INDEX_KEY: self.device.index_key(), VAULT_KEY: self.device.vault_key()},
            created_at=self.device.now(),
            sender=self.device.device_key(),
        )
        return self.device.http.call(
            "PUT", f"/store/person-keys/{device['ed25519']}", {"package": package}, auth=True
        )

    def adopt_person_keys(self) -> bool:
        """Take the person keys that another device of mine left for this device.
        Return True if the keys changed. Then read the personal store."""
        me = self._device_hex()
        try:
            pkg = self.device.http.call("GET", f"/store/person-keys/{me}", auth=True)["package"]
        except NodeHTTPError as exc:
            if exc.status == 404:
                return False
            raise
        state = self.directory.lookup(self.device.subject)
        if not isinstance(pkg, dict) or pkg.get("sender") not in state.devices:
            raise LogMisbehaved("person keys come from a device that is not active for me")
        try:
            keys = open_person_keys(
                pkg,
                hpke.private_from_bytes(self.device.x25519_key().private_bytes()),
                me,
                self.device.subject,
            )
        except FormatError as exc:
            raise ClientError(f"person keys from my other device do not open: {exc}") from exc
        if keys[VAULT_KEY] == self.device.vault_key() and keys[
            INDEX_KEY
        ] == self.device.keystore.get(INDEX_KEY):
            return False
        if keys[VAULT_KEY] != self.device.vault_key() and not self.device.vault.is_empty():
            raise ClientError(
                "this device already has its own findings; it cannot take the person keys"
            )
        index = self.device.home / SNAPSHOT_FILES["index"]
        if index.exists() and keys[INDEX_KEY] != self.device.keystore.get(INDEX_KEY):
            shutil.move(index, index.with_name(index.name + ".replaced"))
        self.device.keystore.replace(VAULT_KEY, keys[VAULT_KEY])
        self.device.keystore.replace(INDEX_KEY, keys[INDEX_KEY])
        self.pull_store()
        return True
