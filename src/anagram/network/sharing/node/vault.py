"""Node vault service: encrypted blobs, grants, public releases, recovery
guardians. See spec/vault.md section 8.

The node stores only ciphertext and public data:

- blobs: chunked AEAD ciphertext (only the client has the content key);
- grants: HPKE ciphertext to recipient devices, the recipient subject, and the
  blob IDs (for the download access check);
- public releases: public by intent (the owner publishes the content key);
- guardian sets: HPKE ciphertext of each share to each guardian device;
- recovery requests: public keys and a node assertion. Approvals are HPKE
  ciphertext to the new device.

The node never receives a content key, a share, a salt, or evidence bytes in
plaintext, except in a public release, which the owner makes public on purpose.
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from anagram.core.crypto.hashing import TAG_SIGN_KEY_POSSESSION
from anagram.core.crypto.signing import verify
from anagram.core.errors import Conflict, Forbidden, FormatError, NodeError, NotFound
from anagram.core.shared_db import SharedDB
from anagram.identity.api import (
    RECOVERY_REQUEST_MAX_AGE,
    possession_message,
    recovery_request_id,
    validate_approval,
    validate_guardian_set,
    validate_recovery_request,
    verify_assertion,
)
from anagram.network.formats.vault import validate_grant, validate_public_release

_HEX16 = re.compile(r"^[0-9a-f]{32}$")
DEFAULT_MAX_BLOB = 4 << 30  # 4 GiB

_SCHEMA = """
CREATE TABLE IF NOT EXISTS blobs (
    blob_id TEXT PRIMARY KEY, owner TEXT NOT NULL, size INTEGER NOT NULL,
    created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
    grant_id TEXT PRIMARY KEY, sender TEXT NOT NULL, recipient TEXT NOT NULL,
    doc TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grant_blobs (
    grant_id TEXT NOT NULL, blob_id TEXT NOT NULL, PRIMARY KEY (grant_id, blob_id));
CREATE TABLE IF NOT EXISTS releases (
    release_id TEXT PRIMARY KEY, owner TEXT NOT NULL, finding_id TEXT NOT NULL,
    doc TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS release_blobs (
    release_id TEXT NOT NULL, blob_id TEXT NOT NULL, PRIMARY KEY (release_id, blob_id));
CREATE TABLE IF NOT EXISTS guardian_sets (
    subject TEXT PRIMARY KEY, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS guardian_index (
    subject TEXT NOT NULL, guardian TEXT NOT NULL, idx INTEGER NOT NULL,
    PRIMARY KEY (subject, guardian));
CREATE TABLE IF NOT EXISTS recovery_requests (
    request_id TEXT PRIMARY KEY, subject TEXT NOT NULL, set_id TEXT NOT NULL,
    doc TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (
    request_id TEXT NOT NULL, idx INTEGER NOT NULL, guardian TEXT NOT NULL,
    doc TEXT NOT NULL, PRIMARY KEY (request_id, idx));
"""


def check_blob_id(blob_id: str) -> str:
    if not isinstance(blob_id, str) or not _HEX16.match(blob_id):
        raise NotFound("unknown blob")
    return blob_id


class NodeVault:
    def __init__(
        self, db_path: str | Path, blob_dir: str | Path, identity, max_blob: int = DEFAULT_MAX_BLOB
    ) -> None:
        self.identity = identity
        self.max_blob = max_blob
        self.blob_dir = Path(blob_dir)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = SharedDB(db_path)
        self._db.executescript(_SCHEMA)
        # The receipt gate (`ReadLedger.serve`). None: no gate.
        self.read_gate = None
        # `reader(subject, blob_id) -> bool` hooks (lab blobs; no gate).
        self.readers: list = []

    def _one(self, sql: str, *args):
        return self._db.execute(sql, args).fetchone()

    def now(self) -> int:
        return self.identity.now()

    # --------------------------------------------------------------- blobs

    def blob_owner(self, blob_id: str) -> str | None:
        with self._lock:
            row = self._one("SELECT owner FROM blobs WHERE blob_id = ?", check_blob_id(blob_id))
            return row[0] if row else None

    def check_upload(self, subject: str, blob_id: str) -> None:
        """Call before the upload. A blob ID belongs to its first uploader."""
        self.identity.require_member(subject)
        owner = self.blob_owner(blob_id)
        if owner is not None and owner != subject:
            raise Conflict("blob ID is in use")

    def temp_path(self, blob_id: str) -> Path:
        return self.blob_dir / f".{check_blob_id(blob_id)}.{os.urandom(6).hex()}.part"

    def store_blob(self, subject: str, blob_id: str, temp: Path) -> dict:
        """Move an uploaded temp file into place (atomic rename)."""
        size = temp.stat().st_size
        if size > self.max_blob:
            temp.unlink()
            raise NodeError("blob is too large")
        with self._lock:
            self.check_upload(subject, blob_id)
            os.replace(temp, self.blob_dir / blob_id)
            self._db.execute(
                "INSERT OR REPLACE INTO blobs (blob_id, owner, size, created_at) VALUES (?, ?, ?, ?)",
                (blob_id, subject, size, self.now()),
            )
        return {"blob_id": blob_id, "size": size}

    def blob_path(self, subject: str | None, blob_id: str) -> Path:
        """Access check, in this order: the owner; a public blob (anyone); a
        `readers` hook that says yes (a lab blob for a lab member, no gate);
        a recipient of a grant that lists the blob, through the receipt gate
        (`read_gate`, 428 without a read receipt). All refusals look the same
        (404)."""
        check_blob_id(blob_id)
        with self._lock:
            row = self._one("SELECT owner FROM blobs WHERE blob_id = ?", blob_id)
            if row is None:
                raise NotFound("unknown blob")
            path = self.blob_dir / blob_id
            if subject is not None and row[0] == subject:
                return path
            if self._one("SELECT 1 FROM release_blobs WHERE blob_id = ?", blob_id) is not None:
                return path
            has_grant = subject is not None and bool(self.grants_with_blob(subject, blob_id))
            readers = list(self.readers)
            gate = self.read_gate
        if subject is not None and any(read(subject, blob_id) for read in readers):
            return path
        if not has_grant:
            raise NotFound("unknown blob")
        if gate is not None:
            gate(subject, blob_id=blob_id)
        return path

    def grants_with_blob(self, subject: str, blob_id: str) -> list[str]:
        """IDs of the grants to `subject` that list the blob."""
        with self._lock:
            rows = self._db.execute(
                "SELECT g.grant_id FROM grant_blobs b JOIN grants g ON g.grant_id = b.grant_id"
                " WHERE b.blob_id = ? AND g.recipient = ? ORDER BY g.grant_id",
                (blob_id, subject),
            ).fetchall()
        return [r[0] for r in rows]

    def delete_blob(self, owner: str, blob_id: str) -> dict:
        """The owner removes a blob ("make a new version now"). Refused if a
        public release lists it. Grants that list it lose it."""
        self.identity.require_member(owner)
        check_blob_id(blob_id)
        with self._lock:
            if self.blob_owner(blob_id) != owner:
                raise NotFound("unknown blob")
            if self._one("SELECT 1 FROM release_blobs WHERE blob_id = ?", blob_id):
                raise Conflict("a public release lists this blob")
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM blobs WHERE blob_id = ?", (blob_id,))
                self._db.execute("DELETE FROM grant_blobs WHERE blob_id = ?", (blob_id,))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            (self.blob_dir / blob_id).unlink(missing_ok=True)
        return {"blob_id": blob_id, "deleted": True}

    def _require_own_blobs(self, subject: str, blob_ids: list[str]) -> None:
        for b in blob_ids:
            if self.blob_owner(b) != subject:
                raise Forbidden("a grant can list only blobs that you uploaded")

    # -------------------------------------------------------------- grants

    def put_grant(self, sender: str, doc: dict) -> dict:
        self.identity.require_member(sender)
        try:
            validate_grant(doc)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if not self.identity.is_member(doc["recipient"]):
            raise NotFound("the recipient is not a member of this community")
        with self._lock:
            self._require_own_blobs(sender, doc["blobs"])
            row = self._one(
                "SELECT sender, recipient, doc FROM grants WHERE grant_id = ?", doc["grant_id"]
            )
            if row is not None:
                old = json.loads(row[2])
                if row[0] != sender or row[1] != doc["recipient"] or old["blobs"] != doc["blobs"]:
                    raise Conflict("grant ID is in use")
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "INSERT OR REPLACE INTO grants (grant_id, sender, recipient, doc, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (doc["grant_id"], sender, doc["recipient"], json.dumps(doc), self.now()),
                )
                for b in doc["blobs"]:
                    self._db.execute(
                        "INSERT OR IGNORE INTO grant_blobs (grant_id, blob_id) VALUES (?, ?)",
                        (doc["grant_id"], b),
                    )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {"grant_id": doc["grant_id"]}

    def _grant_row(self, r) -> dict:
        return {"created_at": r[3], "grant": json.loads(r[2]), "sender": r[0], "recipient": r[1]}

    def grants_for(self, subject: str) -> list[dict]:
        """The grants to `subject`. Each wrap has an empty `ciphertext`, so the
        list opens nothing: the full envelope comes from `get_grant`, through
        the receipt gate."""
        self.identity.require_member(subject)
        with self._lock:
            rows = self._db.execute(
                "SELECT sender, recipient, doc, created_at FROM grants WHERE recipient = ?"
                " ORDER BY created_at, grant_id",
                (subject,),
            ).fetchall()
        out = []
        for r in rows:
            g = self._grant_row(r)
            g["grant"]["wraps"] = [{**w, "ciphertext": ""} for w in g["grant"]["wraps"]]
            out.append(g)
        return out

    def grant_meta(self, grant_id: str) -> dict | None:
        with self._lock:
            row = self._one(
                "SELECT sender, recipient FROM grants WHERE grant_id = ?", str(grant_id)
            )
        if row is None:
            return None
        return {"grant_id": grant_id, "recipient": row[1], "sender": row[0]}

    def get_grant(self, subject: str, grant_id: str) -> dict:
        """The full envelope. The sender has no gate; the recipient needs a
        read receipt (`read_gate`)."""
        self.identity.require_member(subject)
        with self._lock:
            row = self._one(
                "SELECT sender, recipient, doc, created_at FROM grants WHERE grant_id = ?", grant_id
            )
            gate = self.read_gate
        if row is None or subject not in (row[0], row[1]):
            raise NotFound("unknown grant")
        if subject != row[0] and gate is not None:
            gate(subject, grant_id=grant_id)
        return self._grant_row(row)

    def delete_grant(self, sender: str, grant_id: str) -> dict:
        """Withdraw a grant ("stop sharing"). Only the sender. The envelope
        and its blob list go; the blobs stay (other grants can list them)."""
        self.identity.require_member(sender)
        with self._lock:
            meta = self.grant_meta(grant_id)
            if meta is None or meta["sender"] != sender:
                raise NotFound("unknown grant")
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM grants WHERE grant_id = ?", (grant_id,))
                self._db.execute("DELETE FROM grant_blobs WHERE grant_id = ?", (grant_id,))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {"deleted": True, "grant_id": grant_id}

    # ------------------------------------------------------ public releases

    def put_release(self, owner: str, doc: dict) -> dict:
        self.identity.require_member(owner)
        try:
            validate_public_release(doc)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if doc["owner"] != owner:
            raise Forbidden("you can publish only your own findings")
        release_id = doc["receipt"]["grant_id"]
        blob_ids = [b["blob_id"] for b in doc["blobs"]]
        with self._lock:
            self._require_own_blobs(owner, blob_ids)
            if self._one("SELECT 1 FROM releases WHERE release_id = ?", release_id):
                raise Conflict("release ID is in use")
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "INSERT INTO releases (release_id, owner, finding_id, doc, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (release_id, owner, doc["finding_id"], json.dumps(doc), self.now()),
                )
                for b in blob_ids:
                    self._db.execute(
                        "INSERT OR IGNORE INTO release_blobs (release_id, blob_id) VALUES (?, ?)",
                        (release_id, b),
                    )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {"release_id": release_id}

    def get_release(self, release_id: str) -> dict:
        with self._lock:
            row = self._one("SELECT doc FROM releases WHERE release_id = ?", str(release_id))
        if row is None:
            raise NotFound("unknown release")
        return json.loads(row[0])

    def list_releases(self, finding_id: str | None = None) -> list[dict]:
        sql = "SELECT release_id, owner, finding_id, created_at FROM releases"
        with self._lock:
            rows = (
                self._db.execute(
                    sql + " WHERE finding_id = ? ORDER BY created_at", (finding_id,)
                ).fetchall()
                if finding_id
                else self._db.execute(sql + " ORDER BY created_at").fetchall()
            )
        return [
            {"created_at": c, "finding_id": f, "owner": o, "release_id": r} for r, o, f, c in rows
        ]

    # ------------------------------------------------------------ guardians

    def put_guardian_set(self, owner: str, doc: dict) -> dict:
        self.identity.require_member(owner)
        try:
            validate_guardian_set(doc)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if doc["subject"] != owner:
            raise Forbidden("a guardian set is for your own subject only")
        for g in doc["guardians"]:
            if not self.identity.is_member(g["subject"]):
                raise NotFound(f"guardian {g['subject']} is not a member of this community")
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "INSERT OR REPLACE INTO guardian_sets (subject, doc) VALUES (?, ?)",
                    (owner, json.dumps(doc)),
                )
                self._db.execute("DELETE FROM guardian_index WHERE subject = ?", (owner,))
                for g in doc["guardians"]:
                    self._db.execute(
                        "INSERT INTO guardian_index (subject, guardian, idx) VALUES (?, ?, ?)",
                        (owner, g["subject"], g["index"]),
                    )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {"set_id": doc["set_id"]}

    def guardian_set(self, owner: str) -> dict | None:
        with self._lock:
            row = self._one("SELECT doc FROM guardian_sets WHERE subject = ?", owner)
        return json.loads(row[0]) if row else None

    def my_guardian_set(self, owner: str) -> dict:
        self.identity.require_member(owner)
        doc = self.guardian_set(owner)
        if doc is None:
            raise NotFound("no guardian set")
        return doc

    def shares_for(self, guardian: str) -> list[dict]:
        """The share wraps that this guardian holds, one item per owner."""
        self.identity.require_member(guardian)
        out = []
        with self._lock:
            rows = self._db.execute(
                "SELECT subject, idx FROM guardian_index WHERE guardian = ? ORDER BY subject",
                (guardian,),
            ).fetchall()
            for owner, idx in rows:
                doc = self.guardian_set(owner)
                if doc is None:
                    continue
                item = doc["guardians"][idx - 1]
                out.append(
                    {
                        "index": idx,
                        "owner": owner,
                        "set_id": doc["set_id"],
                        "threshold": doc["threshold"],
                        "wraps": item["wraps"],
                    }
                )
        return out

    # ------------------------------------------------------------- recovery

    def create_request(self, subject: str, doc: dict) -> dict:
        """A new device of `subject` asks its guardians for help. The session and
        a fresh node assertion for the new device key must both be for `subject`."""
        self.identity.require_member(subject)
        try:
            validate_recovery_request(doc)
            a = verify_assertion(
                doc["assertion"],
                assertion_key=self.identity.key.public_bytes(),
                node_key=self.identity.cfg.node_key,
                audience=bytes.fromhex(doc["device"]["ed25519"]),
                now=self.identity.now_dt(),
            )
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if doc["subject"] != subject or a["subject"] != subject:
            raise Forbidden("the request, the session, and the assertion must agree")
        if not verify(
            bytes.fromhex(doc["device"]["ed25519"]),
            TAG_SIGN_KEY_POSSESSION,
            possession_message(subject, doc["device"]),
            bytes.fromhex(doc["pop"]),
        ):
            raise NodeError("bad proof of possession")
        gset = self.guardian_set(subject)
        if gset is None:
            raise NotFound("you have no recovery guardians")
        rid = recovery_request_id(doc)
        self._expire_requests()
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO recovery_requests"
                " (request_id, subject, set_id, doc, created_at) VALUES (?, ?, ?, ?, ?)",
                (rid, subject, gset["set_id"], json.dumps(doc), self.now()),
            )
        return {"request_id": rid}

    def _expire_requests(self) -> None:
        """Delete recovery requests older than RECOVERY_REQUEST_MAX_AGE, with
        their approvals."""
        cutoff = self.now() - RECOVERY_REQUEST_MAX_AGE
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute(
                    "DELETE FROM approvals WHERE request_id IN"
                    " (SELECT request_id FROM recovery_requests WHERE created_at < ?)",
                    (cutoff,),
                )
                self._db.execute("DELETE FROM recovery_requests WHERE created_at < ?", (cutoff,))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _request(self, request_id: str) -> tuple[str, str, dict, int]:
        with self._lock:
            self._expire_requests()
            row = self._one(
                "SELECT subject, set_id, doc, created_at FROM recovery_requests WHERE request_id = ?",
                str(request_id),
            )
        if row is None:
            raise NotFound("unknown recovery request")
        return row[0], row[1], json.loads(row[2]), row[3]

    def requests_for_guardian(self, guardian: str) -> list[dict]:
        self.identity.require_member(guardian)
        with self._lock:
            self._expire_requests()
            rows = self._db.execute(
                "SELECT r.request_id, r.doc, r.created_at, g.idx FROM recovery_requests r"
                " JOIN guardian_index g ON g.subject = r.subject"
                " JOIN guardian_sets s ON s.subject = r.subject"
                " WHERE g.guardian = ? AND json_extract(s.doc, '$.set_id') = r.set_id"
                " ORDER BY r.created_at",
                (guardian,),
            ).fetchall()
        return [
            {"index": idx, "request": json.loads(d), "request_id": rid, "received_at": c}
            for rid, d, c, idx in rows
        ]

    def get_request_for_guardian(self, guardian: str, request_id: str) -> dict:
        for r in self.requests_for_guardian(guardian):
            if r["request_id"] == request_id:
                return r
        raise NotFound("unknown recovery request")

    def add_approval(self, guardian: str, request_id: str, doc: dict) -> dict:
        with self._lock:
            req = self.get_request_for_guardian(guardian, request_id)
            try:
                validate_approval(doc)
            except FormatError as exc:
                raise NodeError(str(exc)) from exc
            if (
                doc["guardian"] != guardian
                or doc["request_id"] != request_id
                or doc["index"] != req["index"]
            ):
                raise Forbidden("approval does not match your guardian slot")
            self._db.execute(
                "INSERT OR REPLACE INTO approvals (request_id, idx, guardian, doc)"
                " VALUES (?, ?, ?, ?)",
                (request_id, doc["index"], guardian, json.dumps(doc)),
            )
        return {"request_id": request_id, "index": doc["index"]}

    def get_request(self, subject: str, request_id: str) -> dict:
        """The owner reads its request with all approvals so far."""
        with self._lock:
            owner, set_id, doc, _ = self._request(request_id)
            if owner != subject:
                raise NotFound("unknown recovery request")
            gset = self.guardian_set(owner)
            approvals = [
                json.loads(r[0])
                for r in self._db.execute(
                    "SELECT doc FROM approvals WHERE request_id = ? ORDER BY idx", (request_id,)
                ).fetchall()
            ]
        return {
            "approvals": approvals,
            "backup_id": gset["backup_id"] if gset else None,
            "request": doc,
            "request_id": request_id,
            "set_id": set_id,
            "threshold": gset["threshold"] if gset and gset["set_id"] == set_id else None,
        }
