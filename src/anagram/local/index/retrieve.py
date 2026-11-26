"""Scoped retrieval.

`search(index, query, scope=...)` gives the best chunks of the current
versions of present items, only in the spaces of `scope`. The scope filter is
in the SQL that loads the hit rows (`source_state.space`; a source with no
state row is private), so a hit outside the scope is never built.

Ranking: full-text search (FTS5, BM25) and, with an embedder, vector search.
The two rankings merge by reciprocal rank fusion (`fused`, the code that was
in `LocalIndex.search`). The search asks for a pool of `max(10 * k, 200)`
chunks, and doubles the pool at most 3 times when fewer than `k` hits stay
after the scope and the filters.

Two chunk classes:

- `own`: the table `chunk` (the owner's text).
- `context`: the table `context_chunk` (text that other people wrote:
  quoted mail, received messages). A context hit comes only from
  an item of the private space, and only when `private` is in the scope. It
  has `third_party = True`. Full-text only: context text is not embedded.

An item of kind `noise` is left out unless the caller names the kind. At most
`per_item` chunks of one item are kept.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from anagram.local.index.local import RRF_K, LocalIndex, SearchHit
from anagram.local.index.spaces import PRIVATE, ScopeError
from anagram.local.index.store import placeholders
from anagram.local.index.store_port import Filter
from anagram.local.sources import source_state
from anagram.local.understanding import kinds as kinds_mod
from anagram.local.understanding import titles

OWN = "own"
CONTEXT = "context"
MAX_ROUNDS = 3  # the pool doubles at most this many times
MAX_K = 100
CONTEXT_FILTER = Filter(third_party=True)


@dataclass(frozen=True)
class Hit(SearchHit):
    item_ref: str  # "item:<id>"
    space: str
    kind: str | None
    title: str | None
    time: str | None
    third_party: bool = False
    item_id: int = 0
    chunk_class: str = OWN

    def json(self) -> dict:
        """The hit for a route: no source id, no key, no path."""
        return {
            "anchor": self.anchor,
            "item_ref": self.item_ref,
            "kind": self.kind,
            "score": round(self.score, 6),
            "space": self.space,
            "text": self.text,
            "third_party": self.third_party,
            "time": self.time,
            "title": self.title,
            "via": list(self.via),
        }


class _Vector:
    """The query vector, made one time for all rounds."""

    def __init__(self, index: LocalIndex, query: str) -> None:
        self.index = index
        self.query = query
        self.vector: list[float] | None = None
        self.ready = False

    def get(self) -> list[float] | None:
        if self.ready:
            return self.vector
        self.ready = True
        emb = self.index.embedder
        store = self.index.store
        if emb is None or not store.has_vec() or not self.query.strip():
            return None
        if store.get_meta("embedder") != emb.ident():
            return None
        self.vector = list(emb.embed([self.query])[0])
        return self.vector


def fused(
    index: LocalIndex, query: str, pool: int, vector: _Vector | None = None
) -> tuple[dict[int, float], dict[int, set[str]]]:
    """Reciprocal rank fusion of the full-text and the vector ranking of the
    own chunks: chunk id -> score, and chunk id -> the rankings that found it.
    The two rankings come from the retrieval store port (`store_port`)."""
    ranked: dict[int, float] = {}
    via: dict[int, set[str]] = {}
    for rank, cid in enumerate(index.retrieval.text_search(query, pool)):
        ranked[cid] = ranked.get(cid, 0.0) + 1.0 / (RRF_K + rank + 1)
        via.setdefault(cid, set()).add("text")
    vec = (vector or _Vector(index, query)).get()
    if vec is not None:
        for rank, cid in enumerate(index.retrieval.vector_search(vec, pool)):
            ranked[cid] = ranked.get(cid, 0.0) + 1.0 / (RRF_K + rank + 1)
            via.setdefault(cid, set()).add("vector")
    return ranked, via


def _context_ranked(index: LocalIndex, query: str, pool: int) -> dict[int, float]:
    found = index.retrieval.text_search(query, pool, CONTEXT_FILTER)
    return {cid: 1.0 / (RRF_K + rank + 1) for rank, cid in enumerate(found)}


def check(scope: Iterable[str]) -> frozenset[str]:
    """The scope as a set of space values. An empty scope or a value that is
    not a space is refused (the caller made the scope with `check_scope` or
    `readable_spaces`; this check is a second guard)."""
    out = frozenset(scope)
    if not out:
        raise ScopeError("the scope is empty")
    for s in out:
        if not isinstance(s, str) or not (s == PRIVATE or s.startswith("lab:")):
            raise ScopeError("the scope has a value that is not a space")
    return out


def _rows(
    index: LocalIndex,
    table: str,
    ids: Sequence[int],
    spaces: frozenset[str],
    since: str | None,
    until: str | None,
) -> list:
    """The chunk rows of `ids` in the current version of a present item of a
    source in `spaces`. The scope is applied here, in SQL."""
    out = []
    space_list = sorted(spaces)
    for start in range(0, len(ids), 400):
        part = list(ids[start : start + 400])
        sql = (
            "SELECT c.id, c.anchor, c.text, v.n, v.id AS vid, i.id AS iid, i.source_id, i.key,"  # noqa: S608
            " i.name, i.time, coalesce(ss.space, ?) AS space"
            f" FROM {table} c JOIN version v ON v.id = c.version_id"
            " JOIN item i ON i.id = v.item_id"
            " LEFT JOIN source_state ss ON ss.source_id = i.source_id"
            f" WHERE c.id IN ({placeholders(len(part))})"
            " AND i.present = 1"
            " AND v.n = (SELECT max(n) FROM version WHERE item_id = i.id)"
            " AND coalesce(ss.status, '') != ?"
            f" AND coalesce(ss.space, ?) IN ({placeholders(len(space_list))})"
        )
        args: list = [PRIVATE, *part, source_state.REMOVING, PRIVATE, *space_list]
        if since:
            sql += " AND i.time >= ?"
            args.append(since)
        if until:
            sql += " AND i.time < ?"
            args.append(until)
        out += index.store.q(sql, args)
    return out


def search(
    index: LocalIndex,
    query: str,
    *,
    scope: frozenset[str],
    k: int = 10,
    kinds: Sequence[str] = (),
    since: str | None = None,
    until: str | None = None,
    per_item: int = 2,
    context: bool = True,
) -> list[Hit]:
    """The best `k` chunks for `query` in the spaces of `scope` (see the
    module text). `context=False` leaves out the context class (for a caller
    that must never read other people's text: proposals, lens, MCP)."""
    scope = check(scope)
    k = max(1, min(int(k), MAX_K))
    want = frozenset(kinds)
    if want - set(kinds_mod.KIND_IDS):
        raise ValueError("unknown kind")
    if not query.strip():
        return []
    vector = _Vector(index, query)
    with_context = context and PRIVATE in scope
    pool = max(10 * k, 200)
    hits: list[Hit] = []
    for _ in range(MAX_ROUNDS + 1):
        own, via = fused(index, query, pool, vector)
        ctx = _context_ranked(index, query, pool) if with_context else {}
        found: list[tuple[str, object, float, tuple[str, ...]]] = []
        for r in _rows(index, "chunk", list(own), scope, since, until):
            found.append((OWN, r, own[r["id"]], tuple(sorted(via[r["id"]]))))
        if ctx:
            private = frozenset({PRIVATE})
            for r in _rows(index, "context_chunk", list(ctx), private, since, until):
                found.append((CONTEXT, r, ctx[r["id"]], ("text",)))
        got = kinds_mod.kinds_of(index, {r["vid"] for _, r, _, _ in found})
        hits = []
        for cls, r, score, ways in found:
            ik = got.get(r["vid"])
            kind = ik.kind if ik else None
            if want and kind not in want:
                continue
            if not want and kind == "noise":
                continue
            hits.append(
                Hit(
                    source_id=r["source_id"],
                    key=r["key"],
                    name=r["name"],
                    version=r["n"],
                    anchor=r["anchor"],
                    text=r["text"],
                    score=score,
                    via=ways,
                    item_ref=f"item:{r['iid']}",
                    space=r["space"],
                    kind=kind,
                    title=(ik.title if ik else None) or titles.humanize(r["name"] or "") or None,
                    time=r["time"],
                    third_party=cls == CONTEXT,
                    item_id=r["iid"],
                    chunk_class=cls,
                )
            )
        hits.sort(key=lambda h: (-h.score, h.chunk_class, h.item_id, h.anchor))
        per: dict[str, int] = defaultdict(int)
        kept = []
        for h in hits:
            if per[h.item_ref] >= per_item:
                continue
            per[h.item_ref] += 1
            kept.append(h)
        hits = kept
        exhausted = len(own) < pool and len(ctx) < pool
        if len(hits) >= k or exhausted:
            break
        pool *= 2
    return hits[:k]
