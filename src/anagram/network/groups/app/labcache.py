"""The local lab cache `labspace.sqlite`.

SQLCipher through `anagram.local.localdb`. The key is the keystore entry
`lab-cache-key` (32 bytes, device-local, not in the recovery backup). The
cache holds the verified roster of each lab (the pinned head), the invite
authorisations, the lab items that this device opened, and the publish map.
It is a cache: a device builds it again from the node.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.crypto import aead
from anagram.local.api import connect
from anagram.network.formats import lab as labfmt
from anagram.network.ports import AdmissionCheck

CACHE_FILE = "labspace.sqlite"
CACHE_KEY = "lab-cache-key"
CACHE_INFO = b"anagram.labspace.sqlcipher.v1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS roster (lab_id TEXT, seq INTEGER, entry TEXT, hash TEXT,
    PRIMARY KEY (lab_id, seq));
CREATE TABLE IF NOT EXISTS lab (lab_id TEXT PRIMARY KEY, state TEXT NOT NULL,
    cursor INTEGER NOT NULL DEFAULT 0, epoch INTEGER NOT NULL DEFAULT 0, settings TEXT,
    left INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS invite (lab_id TEXT, invite_id TEXT, auth TEXT NOT NULL,
    PRIMARY KEY (lab_id, invite_id));
CREATE TABLE IF NOT EXISTS item (lab_id TEXT, item_id TEXT, rev INTEGER, value TEXT NOT NULL,
    text TEXT NOT NULL, deleted INTEGER NOT NULL, PRIMARY KEY (lab_id, item_id));
CREATE TABLE IF NOT EXISTS published (lab_id TEXT, source_id TEXT, key TEXT,
    item_id TEXT NOT NULL, version_n INTEGER NOT NULL, PRIMARY KEY (lab_id, source_id, key));
"""

# Columns of the lab keys: `epoch_seq` is the roster seq at the start of the
# current epoch (from the key package); `due` is 1 when a device in the wraps
# of the current epoch is not active now.
_ADDED = (("epoch_seq", "INTEGER NOT NULL DEFAULT -1"), ("due", "INTEGER NOT NULL DEFAULT 0"))
_COLUMNS = ("cursor", "epoch", "settings", "left", "epoch_seq", "due")
_GET = {c: f"SELECT {c} FROM lab WHERE lab_id = ?" for c in _COLUMNS}  # noqa: S608
_SET = {c: f"UPDATE lab SET {c} = ? WHERE lab_id = ?" for c in _COLUMNS}  # noqa: S608
_FORGET = tuple(
    f"DELETE FROM {t} WHERE lab_id = ?"  # noqa: S608 - fixed table names
    for t in ("roster", "invite", "item", "published")
)


class LabCache:
    def __init__(self, home: Path, keystore, admission_check: AdmissionCheck | None) -> None:
        """`admission_check`: the checks of the `invite` and `join` roster
        entries (L4) for `state`. None: the cache reads only items and names."""
        self.admission_check = admission_check
        key = keystore.get_or_create(CACHE_KEY, aead.new_key)
        self._db = connect(Path(home) / CACHE_FILE, key, CACHE_INFO)
        self._db.executescript(_SCHEMA)
        # Two threads can open a new cache at the same time: the write lock
        # of BEGIN IMMEDIATE makes the second one see the added columns.
        self._db.execute("BEGIN IMMEDIATE")
        try:
            have = {r[1] for r in self._db.execute("PRAGMA table_info(lab)")}
            for name, decl in _ADDED:
                if name not in have:
                    self._db.execute(f"ALTER TABLE lab ADD COLUMN {name} {decl}")
            # The lab-space bridge: `auto` is 1 for an item that the lab-space bridge
            # published because its source is in the lab space (it withdraws
            # such an item when the source leaves the space), 0 for an item
            # that the person put into the lab space by hand.
            have = {r[1] for r in self._db.execute("PRAGMA table_info(published)")}
            if "auto" not in have:
                self._db.execute("ALTER TABLE published ADD COLUMN auto INTEGER NOT NULL DEFAULT 0")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")
        self._lock = threading.RLock()

    def close(self) -> None:
        self._db.close()

    # ------------------------------------------------------------- roster

    def labs(self, include_left: bool = False) -> list[str]:
        sql = (
            "SELECT lab_id FROM lab ORDER BY lab_id"
            if include_left
            else "SELECT lab_id FROM lab WHERE left = 0 ORDER BY lab_id"
        )
        return [r[0] for r in self._db.execute(sql)]

    def entries(self, lab_id: str) -> list[dict]:
        return [
            json.loads(e)
            for (e,) in self._db.execute(
                "SELECT entry FROM roster WHERE lab_id = ? ORDER BY seq", (lab_id,)
            )
        ]

    def auths(self, lab_id: str) -> dict[str, dict]:
        return {
            iid: json.loads(a)
            for iid, a in self._db.execute(
                "SELECT invite_id, auth FROM invite WHERE lab_id = ?", (lab_id,)
            )
        }

    def state(self, lab_id: str) -> labfmt.LabState | None:
        """The pinned state: the cached chain, applied again. Each entry was
        verified when it came in, so the device check is not run again."""
        entries = self.entries(lab_id)
        if not entries:
            return None
        return labfmt.replay(
            lab_id, entries, lambda *_: True, self.auths(lab_id), admission=self.admission_check
        )

    def append(self, state: labfmt.LabState, entries: list[dict], auths: dict[str, dict]) -> None:
        """Store verified entries and the state after them in one transaction."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                for e in entries:
                    self._db.execute(
                        "INSERT OR REPLACE INTO roster (lab_id, seq, entry, hash) VALUES (?, ?, ?, ?)",
                        (state.lab_id, e["seq"], canonical_json(e).decode(), labfmt.entry_hash(e)),
                    )
                for iid, auth in auths.items():
                    self._db.execute(
                        "INSERT OR REPLACE INTO invite (lab_id, invite_id, auth) VALUES (?, ?, ?)",
                        (state.lab_id, iid, canonical_json(auth).decode()),
                    )
                summary = json.dumps({"head": state.head, "name": state.name, "seq": state.seq})
                self._db.execute(
                    "INSERT INTO lab (lab_id, state) VALUES (?, ?) ON CONFLICT (lab_id)"
                    " DO UPDATE SET state = excluded.state",
                    (state.lab_id, summary),
                )
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    # ---------------------------------------------------------------- lab

    def _get(self, lab_id: str, column: str):
        row = self._db.execute(_GET[column], (lab_id,)).fetchone()
        return row[0] if row else None

    def _set(self, lab_id: str, column: str, value) -> None:
        self._db.execute(_SET[column], (value, lab_id))

    def left(self, lab_id: str) -> bool:
        return bool(self._get(lab_id, "left"))

    def set_left(self, lab_id: str, left: bool = True) -> None:
        self._set(lab_id, "left", int(left))

    def cursor(self, lab_id: str) -> int:
        return int(self._get(lab_id, "cursor") or 0)

    def set_cursor(self, lab_id: str, value: int) -> None:
        self._set(lab_id, "cursor", int(value))

    def epoch(self, lab_id: str) -> int:
        return int(self._get(lab_id, "epoch") or 0)

    def set_epoch(self, lab_id: str, value: int) -> None:
        self._set(lab_id, "epoch", int(value))

    def epoch_seq(self, lab_id: str) -> int:
        value = self._get(lab_id, "epoch_seq")
        return -1 if value is None else int(value)

    def set_epoch_seq(self, lab_id: str, value: int) -> None:
        self._set(lab_id, "epoch_seq", int(value))

    def due(self, lab_id: str) -> bool:
        return bool(self._get(lab_id, "due"))

    def set_due(self, lab_id: str, due: bool) -> None:
        self._set(lab_id, "due", int(due))

    def settings(self, lab_id: str) -> dict | None:
        raw = self._get(lab_id, "settings")
        return json.loads(raw) if raw else None

    def set_settings(self, lab_id: str, doc: dict) -> None:
        self._set(lab_id, "settings", canonical_json(doc).decode())

    def forget(self, lab_id: str) -> None:
        """Drop the roster, items, and publish map of one lab (the keys stay
        as sealed vault items)."""
        with self._lock:
            for sql in _FORGET:
                self._db.execute(sql, (lab_id,))
            self._db.execute(
                "UPDATE lab SET cursor = 0, settings = NULL, left = 1 WHERE lab_id = ?", (lab_id,)
            )

    # --------------------------------------------------------------- items

    def put_item(self, lab_id: str, value: dict, text: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO item (lab_id, item_id, rev, value, text, deleted)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                lab_id,
                value["item_id"],
                value["rev"],
                canonical_json(value).decode(),
                text,
                int(value["deleted"]),
            ),
        )

    def item(self, lab_id: str, item_id: str) -> tuple[dict, str] | None:
        row = self._db.execute(
            "SELECT value, text FROM item WHERE lab_id = ? AND item_id = ?", (lab_id, item_id)
        ).fetchone()
        return (json.loads(row[0]), row[1]) if row else None

    def items(self, lab_id: str, include_deleted: bool = False) -> list[tuple[dict, str]]:
        sql = "SELECT value, text FROM item WHERE lab_id = ?"
        if not include_deleted:
            sql += " AND deleted = 0"
        return [
            (json.loads(v), t) for v, t in self._db.execute(sql + " ORDER BY item_id", (lab_id,))
        ]

    def set_published(
        self, lab_id: str, source_id: str, key: str, item_id: str, n: int, auto: bool = False
    ) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO published (lab_id, source_id, key, item_id, version_n, auto)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (lab_id, source_id, key, item_id, n, int(auto)),
        )

    def published_rows(self, lab_id: str) -> list[dict]:
        """The publish map of one lab: {"source_id", "key", "item_id",
        "version_n", "auto"} for each index item that this device published."""
        return [
            {"auto": bool(a), "item_id": i, "key": k, "source_id": s, "version_n": int(n)}
            for s, k, i, n, a in self._db.execute(
                "SELECT source_id, key, item_id, version_n, auto FROM published"
                " WHERE lab_id = ? ORDER BY source_id, key",
                (lab_id,),
            )
        ]

    def drop_published(self, lab_id: str, source_id: str, key: str) -> None:
        self._db.execute(
            "DELETE FROM published WHERE lab_id = ? AND source_id = ? AND key = ?",
            (lab_id, source_id, key),
        )

    def published(self, lab_id: str, source_id: str, key: str) -> tuple[str, int] | None:
        row = self._db.execute(
            "SELECT item_id, version_n FROM published WHERE lab_id = ? AND source_id = ?"
            " AND key = ?",
            (lab_id, source_id, key),
        ).fetchone()
        return (row[0], int(row[1])) if row else None

    def name(self, lab_id: str) -> str:
        """The lab name of the verified roster (cache), or ""."""
        raw = self._db.execute("SELECT state FROM lab WHERE lab_id = ?", (lab_id,)).fetchone()
        return str(json.loads(raw[0]).get("name") or "") if raw else ""
