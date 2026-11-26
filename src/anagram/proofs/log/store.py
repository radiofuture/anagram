"""Append-only Merkle log stored in SQLite.

The store keeps each entry and the hash of each complete, aligned subtree
(level, index). Level 0 holds the leaf hashes. From these nodes the store makes
RFC 6962 roots, inclusion proofs, consistency proofs, and C2SP tlog-tiles
hash tiles and entry bundles.

Deviation from C2SP tlog-tiles: the store does not keep tile files on disk.
It derives each tile from the node table on request. The bytes and the paths are
the same as in the tlog-tiles spec.
"""

from __future__ import annotations

from pathlib import Path

from anagram.core.crypto import merkle
from anagram.core.shared_db import SharedDB

TILE_HEIGHT = 8
TILE_WIDTH = 1 << TILE_HEIGHT
MAX_ENTRY_LEN = 0xFFFF


class LogError(ValueError):
    pass


def tile_index_path(n: int) -> str:
    """Encode a tile index as C2SP tlog-tiles path elements (x001/x234/067)."""
    s = str(n)
    s = "0" * (-len(s) % 3) + s
    groups = [s[i : i + 3] for i in range(0, len(s), 3)]
    return "/".join([f"x{g}" for g in groups[:-1]] + [groups[-1]])


def tile_path(level: int | str, index: int, width: int = TILE_WIDTH) -> str:
    p = f"tile/{level}/{tile_index_path(index)}"
    if width < TILE_WIDTH:
        p += f".p/{width}"
    return p


class SQLiteLog:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        # Every call holds one lock: the HTTP threads read while the
        # anchor thread appends (docs/design/shared-sqlite-connection.md).
        self._db = SharedDB(self.path)
        self._lock = self._db.lock
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS entries (idx INTEGER PRIMARY KEY, data BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS nodes (
                level INTEGER NOT NULL, idx INTEGER NOT NULL, hash BLOB NOT NULL,
                PRIMARY KEY (level, idx));
            CREATE TABLE IF NOT EXISTS checkpoints (
                size INTEGER PRIMARY KEY, note TEXT NOT NULL, anchors TEXT NOT NULL);
            """
        )

    def close(self) -> None:
        self._db.close()

    # ------------------------------------------------------------------ write

    def append(self, data: bytes) -> int:
        if len(data) > MAX_ENTRY_LEN:
            raise LogError("entry too large")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                idx = self.size()
                self._db.execute("INSERT INTO entries (idx, data) VALUES (?, ?)", (idx, data))
                level, i, h = 0, idx, merkle.leaf_hash(data)
                self._put_node(level, i, h)
                while i & 1:
                    left = self.node(level, i - 1)
                    h = merkle.node_hash(left, h)
                    level, i = level + 1, i >> 1
                    self._put_node(level, i, h)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            return idx

    def _put_node(self, level: int, idx: int, h: bytes) -> None:
        self._db.execute("INSERT INTO nodes (level, idx, hash) VALUES (?, ?, ?)", (level, idx, h))

    def save_checkpoint(self, size: int, note: str, anchors_json: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO checkpoints (size, note, anchors) VALUES (?, ?, ?)",
                (size, note, anchors_json),
            )

    def set_checkpoint_anchors(self, size: int, anchors_json: str) -> None:
        """Replace the anchor records of a stored checkpoint (background anchors)."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE checkpoints SET anchors = ? WHERE size = ?", (anchors_json, size)
            )
            if cur.rowcount != 1:
                raise LogError(f"no checkpoint at size {size}")

    # ------------------------------------------------------------------- read

    def size(self) -> int:
        row = self._db.execute("SELECT COUNT(*) FROM entries").fetchone()
        return int(row[0])

    def entry(self, idx: int) -> bytes:
        row = self._db.execute("SELECT data FROM entries WHERE idx = ?", (idx,)).fetchone()
        if row is None:
            raise LogError("no such entry")
        return bytes(row[0])

    def node(self, level: int, idx: int) -> bytes:
        row = self._db.execute(
            "SELECT hash FROM nodes WHERE level = ? AND idx = ?", (level, idx)
        ).fetchone()
        if row is None:
            raise LogError(f"no node at level {level} index {idx}")
        return bytes(row[0])

    def latest_checkpoint(self) -> tuple[int, str, str] | None:
        row = self._db.execute(
            "SELECT size, note, anchors FROM checkpoints ORDER BY size DESC LIMIT 1"
        ).fetchone()
        return None if row is None else (int(row[0]), row[1], row[2])

    def checkpoint_at(self, size: int) -> tuple[str, str] | None:
        row = self._db.execute(
            "SELECT note, anchors FROM checkpoints WHERE size = ?", (size,)
        ).fetchone()
        return None if row is None else (row[0], row[1])

    # ---------------------------------------------------------------- proofs

    def subtree(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return merkle.EMPTY_ROOT
        if n & (n - 1) == 0 and lo % n == 0:
            return self.node(n.bit_length() - 1, lo // n)
        k = merkle.split_point(n)
        return merkle.node_hash(self.subtree(lo, lo + k), self.subtree(lo + k, hi))

    def _check_size(self, size: int) -> None:
        if not 0 <= size <= self.size():
            raise LogError("tree size out of range")

    def root(self, size: int | None = None) -> bytes:
        size = self.size() if size is None else size
        self._check_size(size)
        return self.subtree(0, size)

    def inclusion_proof(self, index: int, size: int) -> list[bytes]:
        self._check_size(size)
        return merkle.inclusion_path(self.subtree, index, size)

    def consistency_proof(self, old_size: int, new_size: int) -> list[bytes]:
        self._check_size(new_size)
        return merkle.consistency_path(self.subtree, old_size, new_size)

    # ----------------------------------------------------------------- tiles

    def hash_tile(self, level: int, index: int, width: int = TILE_WIDTH) -> bytes:
        """Return a C2SP tlog-tiles hash tile: `width` hashes at tree level 8*level."""
        if not 1 <= width <= TILE_WIDTH:
            raise LogError("bad tile width")
        height = TILE_HEIGHT * level
        first = index * TILE_WIDTH
        have = self.size() >> height
        if first + width > have:
            raise LogError("tile not available")
        return b"".join(self.node(height, first + i) for i in range(width))

    def entry_bundle(self, index: int, width: int = TILE_WIDTH) -> bytes:
        """Return a C2SP tlog-tiles entry bundle (u16 length || data, per entry)."""
        if not 1 <= width <= TILE_WIDTH:
            raise LogError("bad tile width")
        first = index * TILE_WIDTH
        if first + width > self.size():
            raise LogError("tile not available")
        out = []
        for i in range(width):
            data = self.entry(first + i)
            out.append(len(data).to_bytes(2, "big") + data)
        return b"".join(out)
