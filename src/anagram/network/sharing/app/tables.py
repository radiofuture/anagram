"""The local share tables (spec/vault.md sections 12 to
14) and the functions that read and write them.

The tables are in `vault.sqlite`: the `Client` gives `SCHEMA` to `Vault`, and
`ShareStore` reads and writes them
(and the share keys of the vault key-value table). The tables hold only
pids, ids, and times. Names of people are not in them. `vault.sqlite` is
encrypted (SQLCipher).

A share `target` is a pid, `lab:<lab_id>` (the lab space of a lab of the
sharer), or `invite:<invite_id>` (a reader invite that waits for its
claim).
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Protocol

from anagram.core.keyvalue import JsonKeys, KeyValue, TextKeys

INVITE_TARGET = "invite:"  # a share target: a reader invite that waits for its claim
LAB_TARGET = "lab:"  # a share target: the lab space of a lab of the sharer

SCHEMA = """
CREATE TABLE IF NOT EXISTS shares (
    share_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    target TEXT NOT NULL,
    state TEXT NOT NULL,
    set_root TEXT,
    created_at TEXT NOT NULL,
    stopped_at TEXT,
    UNIQUE (finding_id, target));
CREATE TABLE IF NOT EXISTS share_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    root TEXT,
    person TEXT,
    target TEXT NOT NULL,
    kind TEXT NOT NULL,
    at TEXT NOT NULL,
    detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS share_events_by_finding ON share_events (finding_id, id);
CREATE TABLE IF NOT EXISTS reads (
    receipt_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    root TEXT NOT NULL,
    reader TEXT NOT NULL,
    reader_key TEXT NOT NULL,
    read_at TEXT NOT NULL,
    receipt TEXT NOT NULL,
    log TEXT NOT NULL,
    verified INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS reads_by_grant ON reads (grant_id);
CREATE TABLE IF NOT EXISTS fetch_events (
    grant_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (grant_id, seq));
CREATE TABLE IF NOT EXISTS received (
    grant_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    root TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    received_at TEXT NOT NULL,
    first_opened_at TEXT);
"""

SHARE_EVENT_KINDS = (
    "shared",
    "waiting",
    "key_released",
    "read",
    "stopped",
    "new_version",
    "invite_sent",
    "invite_expired",
    "anomaly",
)


# The keys of L3 sharing in the vault key-value table (text keys; the
# stored values did not change).
QUEUE_PREFIX = "read-receipt-queue/"  # receipt ID -> {"grant_id", "receipt"}
POSTED_PREFIX = "read-receipt-posted/"  # grant ID -> {"posted_at", "receipt_id"}
READING_PREFIX = "reading-copy/"  # root -> blob ID of the uploaded reading copy
GRANT_EXTRA_PREFIX = "grant-extra/"  # grant ID -> extra envelope blob IDs (stable)
REPORT_PREFIX = "received-report/"  # grant ID -> the checked facts of the last open
SEEN_KEY = "shared-seen"  # grant ID -> "waiting" | "ready", for the reader events
INVITE_PREFIX = "reader-invite/"  # invite ID -> {"roots", "state", "subject"} (no contact)
READS_CURSOR = "reads-cursor"  # the read records page of the node, read so far
LAB_ITEM_PREFIX = "lab-share/"  # "<lab_id>/<finding_id>" -> lab item ID of the finding


class ShareVault(KeyValue, Protocol):
    """The local vault as the share store uses it: its connection (the
    tables of `SCHEMA` are in the same file) and its key-value table."""

    @property
    def db(self) -> Any: ...


class ShareStore:
    """The local share tables and the share keys of this device. Sharing
    code reads and writes them only through this object; the composition
    root makes one over the vault and gives it to each sharing part."""

    def __init__(self, vault: ShareVault) -> None:
        self.db = vault.db
        self.receipt_queue = JsonKeys(vault, QUEUE_PREFIX)
        self.receipt_posted = JsonKeys(vault, POSTED_PREFIX)
        self.reading_copy = TextKeys(vault, READING_PREFIX)
        self.grant_extra = JsonKeys(vault, GRANT_EXTRA_PREFIX)
        self.received_report = JsonKeys(vault, REPORT_PREFIX, sort_keys=True)
        self.seen = JsonKeys(vault, SEEN_KEY, sort_keys=True)
        self.invites = JsonKeys(vault, INVITE_PREFIX, sort_keys=True)
        self.reads_cursor = TextKeys(vault, READS_CURSOR)
        self.lab_items = JsonKeys(vault, LAB_ITEM_PREFIX, sort_keys=True)

    # ------------------------------------------------------------------ shares

    def shares_of(self, finding_id: str | None = None) -> list[dict]:
        sql = "SELECT share_id, finding_id, target, state, set_root, created_at, stopped_at FROM shares"
        rows = (
            self.db.execute(sql + " WHERE finding_id = ? ORDER BY created_at", (finding_id,))
            if finding_id
            else self.db.execute(sql + " ORDER BY created_at")
        )
        return [
            {
                "created_at": c,
                "finding_id": f,
                "set_root": sr,
                "share_id": sid,
                "state": st,
                "stopped_at": sa,
                "target": t,
            }
            for sid, f, t, st, sr, c, sa in rows
        ]

    def has_share(self, finding_id: str, target: str) -> bool:
        return (
            self.db.execute(
                "SELECT 1 FROM shares WHERE finding_id = ? AND target = ?", (finding_id, target)
            ).fetchone()
            is not None
        )

    def any_active(self, finding_id: str, target: str, other: str) -> bool:
        """True if the share of a finding with one of the two targets is active."""
        rows = self.db.execute(
            "SELECT state FROM shares WHERE finding_id = ? AND target IN (?, ?)",
            (finding_id, target, other),
        )
        return any(s == "active" for (s,) in rows)

    def put_share(self, finding_id: str, target: str, set_root: str | None, at: str) -> bool:
        """Make the share active. Return True if it is new or was stopped before."""
        row = self.db.execute(
            "SELECT state FROM shares WHERE finding_id = ? AND target = ?", (finding_id, target)
        ).fetchone()
        if row is None:
            self.db.execute(
                "INSERT INTO shares (share_id, finding_id, target, state, set_root, created_at)"
                " VALUES (?, ?, ?, 'active', ?, ?)",
                (secrets.token_hex(16), finding_id, target, set_root, at),
            )
            return True
        if row[0] != "active":
            self.db.execute(
                "UPDATE shares SET state = 'active', stopped_at = NULL, set_root = ?"
                " WHERE finding_id = ? AND target = ?",
                (set_root, finding_id, target),
            )
            return True
        return False

    def stop_share(
        self, finding_id: str, target: str, at: str, *, only_active: bool = False
    ) -> int:
        """Mark the share stopped. Return the number of rows that changed."""
        sql = "UPDATE shares SET state = 'stopped', stopped_at = ? WHERE finding_id = ? AND target = ?"
        if only_active:
            sql += " AND state = 'active'"
        return self.db.execute(sql, (at, finding_id, target)).rowcount

    def add_stopped_share(self, finding_id: str, target: str, at: str) -> None:
        """An explicit stop for a person with no share row (a ring grant)."""
        self.db.execute(
            "INSERT INTO shares (share_id, finding_id, target, state, created_at, stopped_at)"
            " VALUES (?, ?, ?, 'stopped', ?, ?)",
            (secrets.token_hex(16), finding_id, target, at, at),
        )

    def move_invite_share(self, finding_id: str, invite_target: str, subject: str) -> None:
        """The invite share of a finding becomes history of the person who
        claimed it: delete the invite share row and give its events the pid."""
        self.db.execute(
            "DELETE FROM shares WHERE finding_id = ? AND target = ?", (finding_id, invite_target)
        )
        self.db.execute(
            "UPDATE share_events SET person = ? WHERE target = ?", (subject, invite_target)
        )

    # ------------------------------------------------------------ share events

    def add_share_event(
        self,
        *,
        finding_id: str,
        target: str,
        kind: str,
        at: str,
        root: str | None = None,
        person: str | None = None,
        detail: dict | None = None,
    ) -> None:
        if kind not in SHARE_EVENT_KINDS:
            raise ValueError(f"unknown share event kind: {kind}")
        self.db.execute(
            "INSERT INTO share_events (finding_id, root, person, target, kind, at, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (finding_id, root, person, target, kind, at, json.dumps(detail or {}, sort_keys=True)),
        )

    def share_events(self, *, finding_id: str | None = None, person: str | None = None) -> list:
        sql = "SELECT finding_id, root, person, target, kind, at, detail FROM share_events"
        if finding_id is not None:
            rows = self.db.execute(sql + " WHERE finding_id = ? ORDER BY id", (finding_id,))
        elif person is not None:
            rows = self.db.execute(sql + " WHERE person = ? ORDER BY id", (person,))
        else:
            rows = self.db.execute(sql + " ORDER BY id")
        return [
            {
                "at": at,
                "detail": json.loads(d),
                "finding_id": f,
                "kind": k,
                "person": p,
                "root": r,
                "target": t,
            }
            for f, r, p, t, k, at, d in rows
        ]

    # ------------------------------------------------- reads and fetch events

    def reads_of(self, *, grant_id: str | None = None, root: str | None = None) -> list[dict]:
        sql = (
            "SELECT receipt_id, grant_id, root, reader, reader_key, read_at, receipt, log, verified"
            " FROM reads"
        )
        if grant_id is not None:
            rows = self.db.execute(sql + " WHERE grant_id = ? ORDER BY read_at", (grant_id,))
        elif root is not None:
            rows = self.db.execute(sql + " WHERE root = ? ORDER BY read_at", (root,))
        else:
            rows = self.db.execute(sql + " ORDER BY read_at")
        return [
            {
                "grant_id": g,
                "log": json.loads(lg),
                "read_at": at,
                "reader": rd,
                "reader_key": rk,
                "receipt": json.loads(rc),
                "receipt_id": rid,
                "root": rt,
                "verified": bool(v),
            }
            for rid, g, rt, rd, rk, at, rc, lg, v in rows
        ]

    def has_read(self, receipt_id: str) -> bool:
        return (
            self.db.execute("SELECT 1 FROM reads WHERE receipt_id = ?", (receipt_id,)).fetchone()
            is not None
        )

    def add_read(self, receipt_id: str, root: str, receipt: dict, log: dict) -> None:
        """Keep a read receipt that passed all checks."""
        self.db.execute(
            "INSERT INTO reads (receipt_id, grant_id, root, reader, reader_key, read_at,"
            " receipt, log, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (
                receipt_id,
                receipt["grant_id"],
                root,
                receipt["reader"],
                receipt["reader_key"],
                receipt["read_at"],
                json.dumps(receipt, sort_keys=True),
                json.dumps(log, sort_keys=True),
            ),
        )

    def fetch_events_of(self, grant_id: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT event FROM fetch_events WHERE grant_id = ? ORDER BY seq", (grant_id,)
        )
        return [json.loads(r[0]) for r in rows]

    def add_fetch_event(self, event: dict) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO fetch_events (grant_id, seq, event) VALUES (?, ?, ?)",
            (event["grant_id"], event["seq"], json.dumps(event, sort_keys=True)),
        )

    # ---------------------------------------------------------------- received

    def add_received(self, grant_id: str, payload: dict, root: str, at: str) -> None:
        """Keep the row of a received finding (the first open only)."""
        self.db.execute(
            "INSERT INTO received (grant_id, sender, root, finding_id, version, received_at,"
            " first_opened_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (grant_id) DO NOTHING",
            (grant_id, payload["owner"], root, payload["finding_id"], payload["version"], at, at),
        )

    def received_rows(self) -> dict[str, tuple]:
        """grant ID -> (grant_id, sender, root, finding_id, version,
        received_at, first_opened_at)."""
        rows = self.db.execute(
            "SELECT grant_id, sender, root, finding_id, version, received_at, first_opened_at"
            " FROM received"
        )
        return {r[0]: r for r in rows}

    def mark_opened(self, grant_id: str, at: str) -> None:
        self.db.execute(
            "UPDATE received SET first_opened_at = COALESCE(first_opened_at, ?) WHERE grant_id = ?",
            (at, grant_id),
        )
