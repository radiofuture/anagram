"""Local vault (SQLCipher): commitments, sealed opening data, bundles, log state.

The file is encrypted with a device-local key (`anagram.local.localdb`). The opening
data (salts and field values) is also stored only as a sealed opening
(encrypted with the vault key), so that it can go to the personal store.

A vault that an older version wrote as plain SQLite is encrypted in place at
the first open.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import sqlcipher3

from anagram.local import localdb

DB_KEY_INFO = b"anagram.vault.sqlcipher.v1"


@dataclass(frozen=True)
class FindingRow:
    root: str
    finding_id: str
    version: int
    created_at: str
    sealed: dict
    bundle: dict | None


SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    root TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    sealed TEXT NOT NULL,
    bundle TEXT
);
CREATE INDEX IF NOT EXISTS findings_by_id ON findings (finding_id, version);
CREATE TABLE IF NOT EXISTS log_state (
    origin TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    root TEXT NOT NULL,
    checkpoint TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS my_devices (
    ed25519 TEXT PRIMARY KEY,
    x25519 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS directory (
    leaf_index INTEGER PRIMARY KEY,
    subject TEXT NOT NULL,
    entry TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS monitor (
    origin TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    frontier TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    leaf_index INTEGER,
    text TEXT NOT NULL
);
-- P3b. Local file path and flags of each evidence item. The index
-- sets `third_party` = 1 when an item holds other people's words
-- (for example a quoted email). Optional; the default is 0.
CREATE TABLE IF NOT EXISTS evidence_meta (
    root TEXT NOT NULL,
    slot INTEGER NOT NULL,
    path TEXT,
    third_party INTEGER NOT NULL DEFAULT 0,
    blob_id TEXT,
    chunk_size INTEGER,
    size INTEGER,
    PRIMARY KEY (root, slot)
);
-- Sealed items (vault key): content keys, sent grant payload parts,
-- the matching profile. `kind` and `ref` are not secret.
CREATE TABLE IF NOT EXISTS sealed_items (
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ct TEXT NOT NULL,
    PRIMARY KEY (kind, ref)
);
CREATE TABLE IF NOT EXISTS rings (
    name TEXT PRIMARY KEY,
    position INTEGER NOT NULL UNIQUE,
    members TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grants_sent (
    grant_id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    recipient TEXT NOT NULL,
    devices TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Vault:
    def __init__(self, path: str | Path, key: bytes, tables: Sequence[str] = ()) -> None:
        """`tables`: SQL scripts of other layers that keep their tables in
        this file (the composition root gives the share tables of L3)."""
        path = Path(path)
        if localdb.is_plain_sqlite(path):
            localdb.encrypt_in_place(path, key, DB_KEY_INFO)
        self._db = localdb.connect(path, key, DB_KEY_INFO)
        localdb.erase_plain_leftovers(path)
        self._db.executescript(SCHEMA)
        for script in tables:
            self._db.executescript(script)

    @property
    def db(self) -> sqlcipher3.Connection:
        """The connection. Other layers that keep their tables in this file
        (the `tables` of the constructor) use it for those tables only."""
        return self._db

    def close(self) -> None:
        self._db.close()

    def add_finding(
        self, root: str, finding_id: str, version: int, created_at: str, sealed: dict
    ) -> None:
        self._db.execute(
            "INSERT INTO findings (root, finding_id, version, created_at, sealed)"
            " VALUES (?, ?, ?, ?, ?)",
            (root, finding_id, version, created_at, json.dumps(sealed)),
        )

    def set_bundle(self, root: str, bundle: dict) -> None:
        self._db.execute(
            "UPDATE findings SET bundle = ? WHERE root = ?", (json.dumps(bundle), root)
        )

    def _row(self, r) -> FindingRow:
        return FindingRow(
            r[0], r[1], r[2], r[3], json.loads(r[4]), json.loads(r[5]) if r[5] else None
        )

    def get(self, root: str) -> FindingRow | None:
        r = self._db.execute(
            "SELECT root, finding_id, version, created_at, sealed, bundle FROM findings"
            " WHERE root = ?",
            (root,),
        ).fetchone()
        return self._row(r) if r else None

    def find(self, ref: str) -> FindingRow:
        """Find by root or finding_id (full or unique prefix). For a finding_id,
        return the latest version."""
        ref = ref.lower()
        if not ref or any(c not in "0123456789abcdef" for c in ref):
            raise KeyError("reference must be hex")
        rows = self._db.execute(
            "SELECT root, finding_id, version, created_at, sealed, bundle FROM findings"
            " WHERE substr(root, 1, ?) = ? OR substr(finding_id, 1, ?) = ?"
            " ORDER BY version DESC",
            (len(ref), ref, len(ref), ref),
        ).fetchall()
        by_root = [r for r in rows if r[0].startswith(ref)]
        by_id = [r for r in rows if r[1].startswith(ref)]  # ordered by version desc
        ids = {r[1] for r in by_id}
        if len(by_root) == 1 and not (ids - {by_root[0][1]}):
            return self._row(by_root[0])
        if len(ids) == 1 and not by_root:
            return self._row(by_id[0])
        if not rows:
            raise KeyError(f"no finding matches {ref}")
        raise KeyError(f"reference {ref} is ambiguous")

    def list(self) -> list[FindingRow]:
        rows = self._db.execute(
            "SELECT root, finding_id, version, created_at, sealed, bundle FROM findings"
            " ORDER BY created_at, version"
        ).fetchall()
        return [self._row(r) for r in rows]

    def log_state(self, origin: str) -> tuple[int, str, str] | None:
        r = self._db.execute(
            "SELECT size, root, checkpoint FROM log_state WHERE origin = ?", (origin,)
        ).fetchone()
        return (int(r[0]), r[1], r[2]) if r else None

    def set_log_state(self, origin: str, size: int, root: str, checkpoint: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO log_state (origin, size, root, checkpoint) VALUES (?, ?, ?, ?)",
            (origin, size, root, checkpoint),
        )

    # ------------------------------------------------- identity

    def expect_device(self, device: dict) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO my_devices (ed25519, x25519) VALUES (?, ?)",
            (device["ed25519"], device["x25519"]),
        )

    def expected_devices(self) -> set[str]:
        return {r[0] for r in self._db.execute("SELECT ed25519 FROM my_devices")}

    def add_directory_entry(self, leaf_index: int, subject: str, entry: dict) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO directory (leaf_index, subject, entry) VALUES (?, ?, ?)",
            (leaf_index, subject, json.dumps(entry)),
        )

    def directory_entries(self, subject: str | None = None) -> list[tuple[int, dict]]:
        if subject is None:
            rows = self._db.execute("SELECT leaf_index, entry FROM directory ORDER BY leaf_index")
        else:
            rows = self._db.execute(
                "SELECT leaf_index, entry FROM directory WHERE subject = ? ORDER BY leaf_index",
                (subject,),
            )
        return [(int(i), json.loads(e)) for i, e in rows]

    def monitor_state(self, origin: str) -> tuple[int, list[bytes]]:
        r = self._db.execute(
            "SELECT size, frontier FROM monitor WHERE origin = ?", (origin,)
        ).fetchone()
        if r is None:
            return 0, []
        return int(r[0]), [bytes.fromhex(h) for h in json.loads(r[1])]

    def set_monitor_state(self, origin: str, size: int, frontier: list[bytes]) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO monitor (origin, size, frontier) VALUES (?, ?, ?)",
            (origin, size, json.dumps([h.hex() for h in frontier])),
        )

    def add_alert(self, leaf_index: int | None, text: str) -> None:
        self._db.execute("INSERT INTO alerts (leaf_index, text) VALUES (?, ?)", (leaf_index, text))

    def alerts(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT text FROM alerts ORDER BY id")]

    # ------------------------------------------------- vault, rings (P3b)

    def set_evidence_meta(
        self, root: str, slot: int, path: str | None, third_party: bool = False
    ) -> None:
        self._db.execute(
            "INSERT INTO evidence_meta (root, slot, path, third_party) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (root, slot) DO UPDATE SET path = excluded.path,"
            " third_party = excluded.third_party",
            (root, slot, path, 1 if third_party else 0),
        )

    def flag_third_party(self, root: str, slot: int, flag: bool = True) -> None:
        """Mark an evidence item as holding third-party text. A grant of the
        finding then needs an explicit acknowledgement."""
        self._db.execute(
            "INSERT INTO evidence_meta (root, slot, third_party) VALUES (?, ?, ?)"
            " ON CONFLICT (root, slot) DO UPDATE SET third_party = excluded.third_party",
            (root, slot, 1 if flag else 0),
        )

    def set_blob(self, root: str, slot: int, blob_id: str, chunk_size: int, size: int) -> None:
        self._db.execute(
            "INSERT INTO evidence_meta (root, slot, blob_id, chunk_size, size)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT (root, slot) DO UPDATE SET"
            " blob_id = excluded.blob_id, chunk_size = excluded.chunk_size, size = excluded.size",
            (root, slot, blob_id, chunk_size, size),
        )

    def clear_blob(self, root: str, slot: int) -> None:
        """Forget the node blob of an evidence item (the node deleted it)."""
        self._db.execute(
            "UPDATE evidence_meta SET blob_id = NULL, chunk_size = NULL, size = NULL"
            " WHERE root = ? AND slot = ?",
            (root, slot),
        )

    def evidence_meta(self, root: str) -> dict[int, dict]:
        rows = self._db.execute(
            "SELECT slot, path, third_party, blob_id, chunk_size, size FROM evidence_meta"
            " WHERE root = ? ORDER BY slot",
            (root,),
        )
        return {
            int(r[0]): {
                "blob_id": r[3],
                "chunk_size": r[4],
                "path": r[1],
                "size": r[5],
                "third_party": bool(r[2]),
            }
            for r in rows
        }

    def put_sealed(self, kind: str, ref: str, nonce: bytes, ct: bytes) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO sealed_items (kind, ref, nonce, ct) VALUES (?, ?, ?, ?)",
            (kind, ref, nonce.hex(), ct.hex()),
        )

    def get_sealed(self, kind: str, ref: str) -> tuple[bytes, bytes] | None:
        r = self._db.execute(
            "SELECT nonce, ct FROM sealed_items WHERE kind = ? AND ref = ?", (kind, ref)
        ).fetchone()
        return (bytes.fromhex(r[0]), bytes.fromhex(r[1])) if r else None

    def rings(self) -> list[dict]:
        rows = self._db.execute("SELECT name, position, members FROM rings ORDER BY position")
        return [{"members": json.loads(m), "name": n, "position": int(p)} for n, p, m in rows]

    def create_ring(self, name: str) -> dict:
        r = self._db.execute("SELECT COALESCE(MAX(position), -1) FROM rings").fetchone()
        try:
            self._db.execute(
                "INSERT INTO rings (name, position, members) VALUES (?, ?, '[]')",
                (name, int(r[0]) + 1),
            )
        except sqlcipher3.IntegrityError as exc:
            raise KeyError(f"ring {name} exists") from exc
        return self.ring(name)

    def ring(self, name: str) -> dict:
        for r in self.rings():
            if r["name"] == name:
                return r
        raise KeyError(f"no ring named {name}")

    def set_ring_members(self, name: str, members: list[str]) -> None:
        self.ring(name)
        self._db.execute(
            "UPDATE rings SET members = ? WHERE name = ?", (json.dumps(sorted(members)), name)
        )

    def add_grant_sent(
        self, grant_id: str, root: str, recipient: str, devices: list[str], created_at: str
    ) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO grants_sent (grant_id, root, recipient, devices, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (grant_id, root, recipient, json.dumps(sorted(devices)), created_at),
        )

    def forget_grant_sent(self, grant_id: str) -> None:
        self._db.execute("DELETE FROM grants_sent WHERE grant_id = ?", (grant_id,))

    def grants_sent(self, root: str | None = None) -> list[dict]:
        sql = "SELECT grant_id, root, recipient, devices, created_at FROM grants_sent"
        rows = (
            self._db.execute(sql + " WHERE root = ? ORDER BY created_at", (root,))
            if root
            else self._db.execute(sql + " ORDER BY created_at")
        )
        return [
            {
                "created_at": c,
                "devices": json.loads(d),
                "grant_id": g,
                "recipient": rcp,
                "root": rt,
            }
            for g, rt, rcp, d, c in rows
        ]

    # ------------------------------------------- personal store (v2 sync)

    def export_findings(self) -> list[dict]:
        """Each finding with its sealed opening, bundle, and evidence flags. The
        local file paths stay on this device (they are not exported)."""
        out = []
        for row in self.list():
            evidence = [
                {
                    "blob_id": m["blob_id"],
                    "chunk_size": m["chunk_size"],
                    "size": m["size"],
                    "slot": slot,
                    "third_party": m["third_party"],
                }
                for slot, m in self.evidence_meta(row.root).items()
            ]
            out.append(
                {
                    "bundle": row.bundle,
                    "created_at": row.created_at,
                    "evidence": evidence,
                    "finding_id": row.finding_id,
                    "root": row.root,
                    "sealed": row.sealed,
                    "version": row.version,
                }
            )
        return out

    def import_finding(self, value: dict) -> None:
        """Add a finding from the personal store, or add its bundle if this vault
        has none. A local bundle stays (it can be newer)."""
        root = value["root"]
        have = self.get(root)
        if have is None:
            self.add_finding(
                root, value["finding_id"], value["version"], value["created_at"], value["sealed"]
            )
        if value.get("bundle") and (have is None or have.bundle is None):
            self.set_bundle(root, value["bundle"])
        for ev in value.get("evidence") or []:
            slot = int(ev["slot"])
            self._db.execute(
                "INSERT INTO evidence_meta (root, slot, third_party) VALUES (?, ?, ?)"
                " ON CONFLICT (root, slot) DO UPDATE SET third_party = excluded.third_party",
                (root, slot, 1 if ev.get("third_party") else 0),
            )
            if ev.get("blob_id"):
                self.set_blob(root, slot, ev["blob_id"], ev["chunk_size"], ev["size"])

    def sealed_items(self) -> list[tuple[str, str, str, str]]:
        """All sealed items: (kind, ref, nonce hex, ct hex)."""
        return list(
            self._db.execute("SELECT kind, ref, nonce, ct FROM sealed_items ORDER BY kind, ref")
        )

    def import_ring(self, ring: dict) -> None:
        """Set the members of a ring from the personal store (make it if new)."""
        names = {r["name"] for r in self.rings()}
        if ring["name"] not in names:
            taken = self._db.execute(
                "SELECT 1 FROM rings WHERE position = ?", (int(ring["position"]),)
            ).fetchone()
            if taken:
                self.create_ring(ring["name"])
            else:
                self._db.execute(
                    "INSERT INTO rings (name, position, members) VALUES (?, ?, '[]')",
                    (ring["name"], int(ring["position"])),
                )
        self.set_ring_members(ring["name"], list(ring["members"]))

    def import_grant_sent(self, g: dict) -> None:
        self.add_grant_sent(g["grant_id"], g["root"], g["recipient"], g["devices"], g["created_at"])

    def is_empty(self) -> bool:
        """True if this vault holds no findings and no sealed items."""
        a = self._db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        b = self._db.execute("SELECT COUNT(*) FROM sealed_items").fetchone()[0]
        return a == 0 and b == 0

    def kv_items(self, prefix: str) -> list[tuple[str, str]]:
        return list(
            self._db.execute(
                "SELECT key, value FROM kv WHERE substr(key, 1, ?) = ? ORDER BY key",
                (len(prefix), prefix),
            )
        )

    def kv_delete(self, key: str) -> None:
        self._db.execute("DELETE FROM kv WHERE key = ?", (key,))

    def kv_get(self, key: str) -> str | None:
        r = self._db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return r[0] if r else None

    def kv_set(self, key: str, value: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, value))
