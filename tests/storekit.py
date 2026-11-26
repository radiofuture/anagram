"""Test tools for the retrieval store port (plan net 01).

- `bm25`: the FTS5 BM25 score (k1 = 1.2, b = 0.75), in plain Python.
- `ExactStore`: a brute-force adapter of `store_port.RetrievalStore`. It is
  the reference of the contract test (`test_store_port.py`).
- `is_top_k`: a result is correct when its scores are the best `k` scores
  (ties can come in any order).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from anagram.local.index.store_port import ALL, Filter, words

_TOKEN = re.compile(r"[^\W_]+")  # unicode61: letters and digits; "_" splits
K1, B = 1.2, 0.75


def tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def bm25(docs: Mapping[int, str], query: str) -> dict[int, float]:
    """The FTS5 `bm25()` score (as a positive number) of each document that
    has a query word. Only for words that the porter stemmer keeps as they
    are (the tests use such words)."""
    toks = {i: tokens(t) for i, t in docs.items()}
    n = len(toks)
    if not n:
        return {}
    avgdl = sum(len(t) for t in toks.values()) / n
    counts = {i: Counter(t) for i, t in toks.items()}
    out: dict[int, float] = {}
    for w in dict.fromkeys(words(query)):
        df = sum(1 for c in counts.values() if w in c)
        if not df:
            continue
        idf = math.log((n - df + 0.5) / (df + 0.5))
        idf = idf if idf > 0 else 1e-6
        for i, c in counts.items():
            tf = c.get(w, 0)
            if tf:
                dl = len(toks[i])
                out[i] = out.get(i, 0.0) + idf * tf * (K1 + 1) / (
                    tf + K1 * (1 - B + B * dl / avgdl)
                )
    return out


def cosine_distance(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return 1.0 - dot / (na * nb)


def matches(meta: Mapping[str, Any], f: Filter) -> bool:
    """`meta` keys: space, tier, source_id, kind, time, current, third_party."""
    if bool(meta.get("third_party")) != f.third_party:
        return False
    checks = (
        (f.spaces, "space"),
        (f.tiers, "tier"),
        (f.source_ids, "source_id"),
        (f.kinds, "kind"),
    )
    for allowed, key in checks:
        if allowed is not None and meta.get(key) not in allowed:
            return False
    t = meta.get("time")
    if f.since and (t is None or t < f.since):
        return False
    if f.until and (t is None or t >= f.until):
        return False
    return not (f.current_only and not meta.get("current"))


class ExactStore:
    """Brute force over all chunks. `meta` must hold `text` and the filter
    fields of `matches`."""

    def __init__(self) -> None:
        self.vectors: dict[int, list[float]] = {}
        # Own chunks and context chunks have their own ID spaces (two tables).
        self.metas: dict[bool, dict[int, dict]] = {False: {}, True: {}}

    def upsert(
        self, chunk_id: int, vector: Sequence[float], meta: Mapping[str, Any] | None = None
    ) -> None:
        meta = dict(meta or {})
        third = bool(meta.get("third_party"))
        if vector and not third:
            self.vectors[chunk_id] = list(vector)
        self.metas[third][chunk_id] = meta

    def delete(self, chunk_ids: Iterable[int]) -> None:
        for cid in chunk_ids:
            self.vectors.pop(cid, None)

    def vector_scores(self, vector: Sequence[float], f: Filter = ALL) -> dict[int, float]:
        """Chunk id -> cosine distance, for the chunks that match `f`."""
        own = self.metas[False]
        return {
            cid: cosine_distance(vector, v)
            for cid, v in self.vectors.items()
            if matches(own[cid], f)
        }

    def text_scores(self, query: str, f: Filter = ALL) -> dict[int, float]:
        """Chunk id -> BM25 (larger is better). The corpus statistics are those
        of the whole class (own or context), as in FTS5."""
        metas = self.metas[f.third_party]
        docs = {cid: m["text"] for cid, m in metas.items()}
        return {cid: s for cid, s in bm25(docs, query).items() if matches(metas[cid], f)}

    def vector_search(self, vector: Sequence[float], k: int, filter: Filter = ALL) -> list[int]:
        scores = self.vector_scores(vector, filter)
        return sorted(scores, key=lambda c: (scores[c], c))[:k]

    def text_search(self, query: str, k: int, filter: Filter = ALL) -> list[int]:
        scores = self.text_scores(query, filter)
        return sorted(scores, key=lambda c: (-scores[c], c))[:k]

    def count(self) -> int:
        return len(self.vectors)

    def close(self) -> None:
        pass


def is_top_k(got: Sequence[int], scores: Mapping[int, float], k: int, *, larger: bool) -> bool:
    """True when `got` is a correct top `k` of `scores`: no repeat, each ID
    has a score, the list is in score order, and its scores are the best `k`
    scores (within a small float tolerance)."""
    if len(set(got)) != len(got) or any(c not in scores for c in got):
        return False
    best = sorted(scores.values(), reverse=larger)[:k]
    mine = [scores[c] for c in got]
    if len(mine) != len(best):
        return False
    tol = 1e-4
    in_order = all(
        (a >= b - tol) if larger else (a <= b + tol) for a, b in zip(mine, mine[1:], strict=False)
    )
    return in_order and all(abs(a - b) <= tol for a, b in zip(mine, best, strict=True))
