"""The present retrieval store: sqlite-vec and FTS5 in the SQLCipher index
(adapter of `store_port.RetrievalStore`).

- Vectors: the `vec0` table `chunk_vec` (float32, cosine). `vec0` is a flat
  index: each search reads all vectors, so the result is exact.
- Text: the FTS5 tables `chunk_fts` (own chunks) and `context_fts` (chunks of
  class `context`), ranked by BM25.

The filter fields come from the index tables (`chunk`, `version`, `item`,
`source_state`), so `upsert` does not use `meta`. A vector search with a
filter asks `vec0` for a pool of the nearest chunks and keeps the chunks that
match; the pool doubles until `k` chunks match or the pool holds all
vectors. So the result stays exact. `tiers` and `kinds` are refused: the
index has no tier column yet, and the kind of an item is a
ranked fact that `retrieve.search` applies above the port.

The adapter does not own the store: `close` does nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from anagram.local.index.spaces import PRIVATE
from anagram.local.index.store import IndexStore, placeholders
from anagram.local.index.store_port import ALL, Filter, UnsupportedFilter, words
from anagram.local.sources import source_state

PART = 400  # IDs in one SQL `IN (...)`
MIN_POOL = 200


def _serialize(vector: Sequence[float]) -> bytes:
    import sqlite_vec

    return sqlite_vec.serialize_float32(list(vector))


def _where(f: Filter) -> tuple[str, list]:
    """The SQL condition of the filter on the joined rows `c` (chunk or
    context chunk), `v` (version), `i` (item), and `ss` (source state)."""
    if f.tiers is not None:
        raise UnsupportedFilter("the index has no trust tier yet")
    if f.kinds is not None:
        raise UnsupportedFilter("filter kinds above the port (retrieve.search)")
    sql: list[str] = []
    args: list = []
    if f.spaces is not None:
        spaces = sorted(f.spaces)
        sql.append(f"coalesce(ss.space, ?) IN ({placeholders(len(spaces))})")
        args += [PRIVATE, *spaces]
    if f.source_ids is not None:
        sids = sorted(f.source_ids)
        sql.append(f"i.source_id IN ({placeholders(len(sids))})")
        args += sids
    if f.since:
        sql.append("i.time >= ?")
        args.append(f.since)
    if f.until:
        sql.append("i.time < ?")
        args.append(f.until)
    if f.current_only:
        sql.append("i.present = 1")
        sql.append("v.n = (SELECT max(n) FROM version WHERE item_id = i.id)")
        sql.append("coalesce(ss.status, '') != ?")
        args.append(source_state.REMOVING)
    return " AND ".join(sql) or "1", args


_JOIN = (
    " JOIN version v ON v.id = c.version_id JOIN item i ON i.id = v.item_id"
    " LEFT JOIN source_state ss ON ss.source_id = i.source_id"
)


class SqliteVecStore:
    """`RetrievalStore` over the open `IndexStore`."""

    def __init__(self, store: IndexStore) -> None:
        self.store = store

    # ------------------------------------------------------------- writes

    def upsert(
        self, chunk_id: int, vector: Sequence[float], meta: Mapping[str, Any] | None = None
    ) -> None:
        """Set the vector of one chunk. The caller holds the transaction and
        has made `chunk_vec` (`IndexStore.ensure_vec`)."""
        self.store.x("DELETE FROM chunk_vec WHERE rowid = ?", (chunk_id,))
        self.store.x(
            "INSERT INTO chunk_vec (rowid, embedding) VALUES (?, ?)",
            (chunk_id, _serialize(vector)),
        )

    def delete(self, chunk_ids: Iterable[int]) -> None:
        if not self.store.has_vec():
            return
        ids = list(chunk_ids)
        for start in range(0, len(ids), PART):
            part = ids[start : start + PART]
            self.store.x(
                f"DELETE FROM chunk_vec WHERE rowid IN ({placeholders(len(part))})",  # noqa: S608
                part,
            )

    # ------------------------------------------------------------- search

    def vector_search(self, vector: Sequence[float], k: int, filter: Filter = ALL) -> list[int]:
        if k <= 0 or filter.third_party or not self.store.has_vec():
            return []  # context chunks have no vectors
        blob = _serialize(vector)
        if filter.is_empty():
            return self._knn(blob, k)
        where, args = _where(filter)
        total = self.count()
        pool = max(10 * k, MIN_POOL)
        while True:
            near = self._knn(blob, min(pool, total))
            keep = self._matching(near, where, args)
            out = [cid for cid in near if cid in keep]
            if len(out) >= k or len(near) >= total:
                return out[:k]
            pool *= 2

    def _knn(self, blob: bytes, k: int) -> list[int]:
        if k <= 0:
            return []
        rows = self.store.q(
            "SELECT rowid, distance FROM chunk_vec WHERE embedding MATCH ? AND k = ?", (blob, k)
        )
        return [r[0] for r in rows]

    def _matching(self, ids: list[int], where: str, args: list) -> set[int]:
        out: set[int] = set()
        for start in range(0, len(ids), PART):
            part = ids[start : start + PART]
            out |= {
                r[0]
                for r in self.store.q(
                    f"SELECT c.id FROM chunk c{_JOIN}"  # noqa: S608
                    f" WHERE c.id IN ({placeholders(len(part))}) AND {where}",
                    [*part, *args],
                )
            }
        return out

    def text_search(self, query: str, k: int, filter: Filter = ALL) -> list[int]:
        found = words(query)
        if not found or k <= 0:
            return []
        table, fts = (
            ("context_chunk", "context_fts") if filter.third_party else ("chunk", "chunk_fts")
        )
        match = " OR ".join(f'"{w}"' for w in found)
        bare = Filter(third_party=filter.third_party)
        if filter == bare:
            sql = f"SELECT rowid FROM {fts} WHERE {fts} MATCH ? ORDER BY rank LIMIT ?"  # noqa: S608
            return [r[0] for r in self.store.q(sql, (match, k))]
        where, args = _where(filter)
        sql = (
            f"SELECT f.rowid FROM {fts} f JOIN {table} c ON c.id = f.rowid{_JOIN}"  # noqa: S608
            f" WHERE {fts} MATCH ? AND {where} ORDER BY f.rank LIMIT ?"
        )
        return [r[0] for r in self.store.q(sql, [match, *args, k])]

    # -------------------------------------------------------------- other

    def count(self) -> int:
        if not self.store.has_vec():
            return 0
        return self.store.one("SELECT count(*) FROM chunk_vec")[0]

    def close(self) -> None:
        """The `LocalIndex` owns the store and closes it."""
