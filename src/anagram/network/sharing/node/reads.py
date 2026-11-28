"""Node read ledger: read receipts, fetch events,
and the receipt gate. See spec/vault.md sections 12 and 13 and
docs/design/two-party-receipt.md.

- A grant recipient posts a signed read receipt before the node serves the
  grant envelope or a blob of the grant ("no receipt, no data": HTTP 428).
- The node checks the receipt, submits its commitment to the log (kind
  `read_receipt`), stores it, and signs fetch event `seq = n` with
  `blob_id = null`. Each gated blob answer adds one more signed event.
- The sender of a grant reads the receipts (with their log proofs) and the
  events with a cursor, and checks them on its own computer.

The owner of a blob, the sender of a grant, and a public blob have no gate.
Own file `reads.sqlite`. The ledger keeps the receipts and events when a grant
is deleted: the owner keeps the read history.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from fastapi import APIRouter, Body, Header

from anagram.core.errors import Forbidden, FormatError, NodeError, NotFound
from anagram.core.shared_db import SharedDB
from anagram.core.timefmt import parse_time
from anagram.network.formats.sharing import (
    make_fetch_event,
    read_receipt_id,
    read_receipt_log_entry,
    verify_read_receipt,
)

DEFAULT_WINDOW_S = 24 * 3600
SKEW_S = 300
MAX_PAGE = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS read_receipts (
    receipt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, sender TEXT NOT NULL,
    reader TEXT NOT NULL, doc TEXT NOT NULL, log TEXT NOT NULL,
    received_at INTEGER NOT NULL, event_id INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS read_receipts_by_reader ON read_receipts (reader, received_at);
CREATE INDEX IF NOT EXISTS read_receipts_by_sender ON read_receipts (sender, event_id);
CREATE TABLE IF NOT EXISTS fetch_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL, seq INTEGER NOT NULL,
    sender TEXT NOT NULL, doc TEXT NOT NULL, UNIQUE (grant_id, seq));
CREATE INDEX IF NOT EXISTS fetch_events_by_sender ON fetch_events (sender, id);
"""


class ReadRequired(NodeError):
    """The reader has no valid read receipt for this grant or blob."""

    status = 428

    def __init__(self) -> None:
        super().__init__("read receipt required")


class ReadLedger:
    """Receipts, fetch events, and the gate (`serve`). The composition root
    gives the gate to the vault (`NodeVault.read_gate`)."""

    def __init__(
        self,
        db_path: str | Path,
        identity,
        vault,
        *,
        window_s: int = DEFAULT_WINDOW_S,
    ) -> None:
        self.identity = identity
        self.vault = vault
        self.window_s = int(window_s)
        self._lock = threading.RLock()
        self._db = SharedDB(db_path)
        self._db.executescript(_SCHEMA)

    def _one(self, sql: str, *args):
        return self._db.execute(sql, args).fetchone()

    def now(self) -> int:
        return self.identity.now()

    # ------------------------------------------------------------- accept

    def accept(self, subject: str, grant_id: str, receipt: dict) -> dict:
        """Check a read receipt of the session subject, log it, and sign the
        first fetch event under it. The same receipt again gives the same
        answer (no second log entry)."""
        self.identity.require_member(subject)
        grant = self.vault.grant_meta(grant_id)
        if grant is None or grant["recipient"] != subject:
            raise NotFound("unknown grant")
        try:
            verify_read_receipt(receipt)
        except FormatError as exc:
            raise NodeError(str(exc)) from exc
        if receipt["grant_id"] != grant_id or receipt["reader"] != subject:
            raise Forbidden("the receipt is for another grant or another reader")
        if receipt["reader_key"] not in self.identity.active_devices(subject):
            raise Forbidden("the receipt key is not an active device key of the reader")
        if parse_time(receipt["read_at"]).timestamp() > self.now() + SKEW_S:
            raise NodeError("the receipt time is in the future")
        rid = read_receipt_id(receipt)
        with self._lock:
            row = self._one(
                "SELECT doc, log, event_id FROM read_receipts WHERE receipt_id = ?", rid
            )
            if row is not None:
                event = self._event_by_id(row[2])
                return {"event": event, "log": json.loads(row[1]), "receipt_id": rid}
            entry = read_receipt_log_entry(receipt)
            result = self.identity.log.submit(entry)
            log = {
                "checkpoint": result["checkpoint"],
                "entry": entry,
                "inclusion": result["inclusion"],
                "leaf_index": result["leaf_index"],
                "tree_size": result["tree_size"],
            }
            self._db.execute("BEGIN")
            try:
                event_id, event = self._add_event(grant, subject, None, rid)
                self._db.execute(
                    "INSERT INTO read_receipts (receipt_id, grant_id, sender, reader, doc, log,"
                    " received_at, event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rid,
                        grant_id,
                        grant["sender"],
                        subject,
                        json.dumps(receipt),
                        json.dumps(log),
                        self.now(),
                        event_id,
                    ),
                )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return {"event": event, "log": log, "receipt_id": rid}

    # --------------------------------------------------------------- gate

    def _valid_receipt(self, subject: str, grant_ids: list[str]) -> tuple[str, str] | None:
        if not grant_ids:
            return None
        row = self._one(
            "SELECT receipt_id, grant_id FROM read_receipts WHERE reader = ?"
            " AND grant_id IN (SELECT value FROM json_each(?)) AND received_at >= ?"
            " ORDER BY received_at DESC, event_id DESC LIMIT 1",
            subject,
            json.dumps(grant_ids),
            self.now() - self.window_s,
        )
        return (row[0], row[1]) if row else None

    def _find(self, subject: str, grant_id: str | None, blob_id: str | None) -> tuple[str, str]:
        if grant_id is not None:
            grants = [grant_id]
        else:
            grants = self.vault.grants_with_blob(subject, blob_id)
        found = self._valid_receipt(subject, grants)
        if found is None:
            raise ReadRequired()
        return found

    def gate(self, subject: str, *, grant_id: str | None = None, blob_id: str | None = None) -> str:
        """The receipt ID that lets `subject` fetch the grant or the blob now.
        Raise ReadRequired (428) if there is none."""
        with self._lock:
            return self._find(subject, grant_id, blob_id)[0]

    def serve(self, subject: str, *, grant_id: str | None = None, blob_id: str | None = None):
        """The hook of NodeVault. A grant envelope: gate only. A blob: gate,
        then one signed fetch event."""
        with self._lock:
            rid, gid = self._find(subject, grant_id, blob_id)
            if blob_id is not None:
                self.record_fetch(subject, gid, blob_id, rid)
            return rid

    # ------------------------------------------------------------- events

    def _add_event(self, grant: dict, reader: str, blob_id: str | None, rid: str):
        (top,) = self._one(
            "SELECT COALESCE(MAX(seq), 0) FROM fetch_events WHERE grant_id = ?", grant["grant_id"]
        )
        event = make_fetch_event(
            at=self.identity.now_dt(),
            grant_id=grant["grant_id"],
            blob_id=blob_id,
            reader=reader,
            receipt_id=rid,
            seq=top + 1,
            node_key=self.identity.cfg.node_key,
            key=self.identity.key,
        )
        cur = self._db.execute(
            "INSERT INTO fetch_events (grant_id, seq, sender, doc) VALUES (?, ?, ?, ?)",
            (grant["grant_id"], event["seq"], grant["sender"], json.dumps(event)),
        )
        return cur.lastrowid, event

    def _event_by_id(self, event_id: int) -> dict:
        return json.loads(self._one("SELECT doc FROM fetch_events WHERE id = ?", event_id)[0])

    def record_fetch(self, subject: str, grant_id: str, blob_id: str | None, receipt_id: str):
        grant = self.vault.grant_meta(grant_id)
        if grant is None:
            raise NotFound("unknown grant")
        with self._lock:
            return self._add_event(grant, subject, blob_id, receipt_id)[1]

    # ------------------------------------------------------------- sender

    def for_sender(self, sender: str, since: int = 0) -> dict:
        """Receipts and events of the grants that `sender` made, after the
        cursor. The cursor is the ID of the last event (each receipt has one
        event, so a receipt comes with or before its first event)."""
        self.identity.require_member(sender)
        since = max(0, int(since))
        with self._lock:
            rows = self._db.execute(
                "SELECT id, doc FROM fetch_events WHERE sender = ? AND id > ? ORDER BY id LIMIT ?",
                (sender, since, MAX_PAGE),
            ).fetchall()
            cursor = rows[-1][0] if rows else since
            receipts = self._db.execute(
                "SELECT doc, log FROM read_receipts WHERE sender = ? AND event_id > ?"
                " AND event_id <= ? ORDER BY event_id",
                (sender, since, cursor),
            ).fetchall()
        return {
            "cursor": cursor,
            "events": [json.loads(d) for _, d in rows],
            "more": len(rows) == MAX_PAGE,
            "receipts": [{"log": json.loads(lg), "receipt": json.loads(d)} for d, lg in receipts],
        }


def reads_router(ledger: ReadLedger, subject_of, field) -> APIRouter:
    """Routes of the read ledger, and the two delete routes of the vault that
    "stop sharing" uses."""
    router = APIRouter()
    vault = ledger.vault

    @router.post("/grants/{grant_id}/receipts")
    def post_receipt(
        grant_id: str,
        body: dict = Body(...),  # noqa: B008
        authorization: str | None = Header(default=None),
    ) -> dict:
        return ledger.accept(subject_of(authorization), grant_id, field(body, "receipt"))

    @router.get("/grants/sent/reads")
    def sent_reads(since: int = 0, authorization: str | None = Header(default=None)) -> dict:
        return ledger.for_sender(subject_of(authorization), since)

    @router.delete("/grants/{grant_id}")
    def delete_grant(grant_id: str, authorization: str | None = Header(default=None)) -> dict:
        return vault.delete_grant(subject_of(authorization), grant_id)

    @router.delete("/blobs/{blob_id}")
    def delete_blob(blob_id: str, authorization: str | None = Header(default=None)) -> dict:
        return vault.delete_blob(subject_of(authorization), blob_id)

    return router
