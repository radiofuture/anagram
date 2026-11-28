"""Personal store on the node (spec/vault.md section 11): ciphertext records of each
person, and person-key packages for new devices.

The node holds only ciphertext. It sees, for each person: opaque record IDs,
versions, sizes, and times. It never has the vault key. Members only. Each
person has a quota (sum of ciphertext bytes).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.crypto.hashing import TAG_SIGN_PERSON_KEYS
from anagram.core.errors import Conflict, Forbidden, FormatError, NodeError, NotFound
from anagram.core.shared_db import SharedDB
from anagram.core.signed import doc_signature_ok
from anagram.identity.formats.personal_store import (
    record_size,
    validate_person_keys,
    validate_record,
)

DEFAULT_QUOTA = 512 << 20  # 512 MiB of ciphertext for each person
MAX_RECORDS = 100_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    subject TEXT NOT NULL, record_id TEXT NOT NULL, version INTEGER NOT NULL,
    size INTEGER NOT NULL, doc TEXT NOT NULL, updated_at INTEGER NOT NULL,
    PRIMARY KEY (subject, record_id));
CREATE TABLE IF NOT EXISTS person_keys (
    subject TEXT NOT NULL, device TEXT NOT NULL, doc TEXT NOT NULL,
    updated_at INTEGER NOT NULL, PRIMARY KEY (subject, device));
"""


class QuotaExceeded(NodeError):
    status = 413


class NodePersonalStore:
    def __init__(self, db_path: str | Path, identity, quota: int = DEFAULT_QUOTA) -> None:
        self.identity = identity
        self.quota = quota
        self._lock = threading.RLock()
        self._db = SharedDB(db_path)
        self._db.executescript(_SCHEMA)

    def _one(self, sql: str, *args):
        return self._db.execute(sql, args).fetchone()

    def used(self, subject: str) -> int:
        return int(
            self._one("SELECT COALESCE(SUM(size), 0) FROM records WHERE subject = ?", subject)[0]
        )

    # ------------------------------------------------------------- records

    def list(self, subject: str) -> dict:
        self.identity.require_member(subject)
        rows = self._db.execute(
            "SELECT record_id, version, size FROM records WHERE subject = ? ORDER BY record_id",
            (subject,),
        )
        return {
            "quota": self.quota,
            "records": [{"record_id": r, "size": s, "version": v} for r, v, s in rows],
            "used": self.used(subject),
        }

    def put(self, subject: str, record_id: str, doc: dict) -> dict:
        self.identity.require_member(subject)
        try:
            validate_record(doc)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if doc["record_id"] != record_id:
            raise NodeError("record_id in the path and in the record differ")
        size = record_size(doc)
        text = canonical_json(doc).decode()
        with self._lock:
            old = self._one(
                "SELECT version, size, doc FROM records WHERE subject = ? AND record_id = ?",
                subject,
                record_id,
            )
            if old is not None:
                if old[2] == text:
                    return {"record_id": record_id, "version": old[0]}  # the same record again
                if doc["version"] <= old[0]:
                    raise Conflict(f"the node has version {old[0]}; send a newer version")
            elif self._one("SELECT COUNT(*) FROM records WHERE subject = ?", subject)[0] >= (
                MAX_RECORDS
            ):
                raise QuotaExceeded("too many records")
            if self.used(subject) - (old[1] if old else 0) + size > self.quota:
                raise QuotaExceeded("personal store quota is full")
            self._db.execute(
                "INSERT OR REPLACE INTO records (subject, record_id, version, size, doc,"
                " updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (subject, record_id, doc["version"], size, text, self.identity.now()),
            )
        return {"record_id": record_id, "version": doc["version"]}

    def get(self, subject: str, record_id: str) -> dict:
        self.identity.require_member(subject)
        row = self._one(
            "SELECT doc FROM records WHERE subject = ? AND record_id = ?", subject, record_id
        )
        if row is None:
            raise NotFound("no such record")
        return {"record": json.loads(row[0])}

    def delete(self, subject: str, record_id: str) -> dict:
        self.identity.require_member(subject)
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM records WHERE subject = ? AND record_id = ?", (subject, record_id)
            )
        if cur.rowcount != 1:
            raise NotFound("no such record")
        return {"deleted": record_id}

    # --------------------------------------------------------- person keys

    def put_person_keys(self, subject: str, device: str, doc: dict) -> dict:
        """A device of the person leaves the person keys for another device of
        the same person. Both must be active in the key directory."""
        self.identity.require_member(subject)
        try:
            validate_person_keys(doc)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        active = self.identity.active_devices(subject)
        if doc["subject"] != subject or doc["recipient"] != device:
            raise Forbidden("person keys are for another person or device")
        if device not in active or doc["sender"] not in active:
            raise Forbidden("sender and recipient must be active devices of this person")
        if not doc_signature_ok(doc, TAG_SIGN_PERSON_KEYS, bytes.fromhex(doc["sender"])):
            raise NodeError("person keys have a bad signature")
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO person_keys (subject, device, doc, updated_at)"
                " VALUES (?, ?, ?, ?)",
                (subject, device, json.dumps(doc), self.identity.now()),
            )
        return {"device": device}

    def get_person_keys(self, subject: str, device: str) -> dict:
        self.identity.require_member(subject)
        row = self._one(
            "SELECT doc FROM person_keys WHERE subject = ? AND device = ?", subject, device
        )
        if row is None:
            raise NotFound("no person keys for this device")
        return {"package": json.loads(row[0])}
