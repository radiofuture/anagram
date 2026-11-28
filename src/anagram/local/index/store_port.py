"""The retrieval store port.

The index keeps chunk vectors and the full-text index behind this port, so
the engine can change without a change to its callers. Hybrid fusion
(reciprocal rank fusion) stays above the port, in `retrieve.py`.

This port is inside L2 (`local/index/`). It is not a cross-layer port. Only
modules in `local/index/` make an adapter; other code gets the adapter as
`LocalIndex.retrieval`.

Adapters:

- `vec_store.SqliteVecStore`: the present store. sqlite-vec `vec0` (float32,
  exact search) and FTS5, in the SQLCipher index file.
- The contract test holds a brute-force reference adapter
  (`tests/storekit.py`).

A filter that an adapter cannot apply is refused (`UnsupportedFilter`). An
adapter never ignores a filter field: a field that it ignores could show a
chunk outside the scope.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


class UnsupportedFilter(ValueError):
    """The adapter cannot apply a field of the filter."""


@dataclass(frozen=True)
class Filter:
    """The chunks that a search may return. `None` (or `False`) for a field
    means "no limit by this field". All set fields must match.

    - `spaces`: the space of the source (`private` or `lab:<id>`).
    - `tiers`: the trust tier of the item (no adapter supports it yet).
    - `source_ids`: the source of the item.
    - `kinds`: the item kind (`local/understanding/kinds.py`).
    - `since`, `until`: the item time, `since <= time < until`.
    - `current_only`: only the current version of a present item of a source
      that is not being removed.
    - `third_party`: search the chunks of class `context` (text that other
      people wrote) in place of the own chunks.
    """

    spaces: frozenset[str] | None = None
    tiers: frozenset[str] | None = None
    source_ids: frozenset[str] | None = None
    kinds: frozenset[str] | None = None
    since: str | None = None
    until: str | None = None
    current_only: bool = False
    third_party: bool = False

    def is_empty(self) -> bool:
        """True when no field limits the search. An empty set is a limit
        (it matches no chunk)."""
        return self == Filter()


ALL = Filter()

_WORD = re.compile(r"\w+")


def words(query: str) -> list[str]:
    """The search words of a text query (lower case)."""
    return _WORD.findall(query.lower())


class RetrievalStore(Protocol):
    """Vector and full-text search over the chunks of the index.

    `vector_search` and `text_search` give chunk IDs, best first. Each adapter
    gives the exact top `k` for its filter, or documents its recall.
    """

    def upsert(
        self, chunk_id: int, vector: Sequence[float], meta: Mapping[str, Any] | None = None
    ) -> None:
        """Set the vector of a chunk. `meta`: the filter fields of the chunk,
        for an adapter that does not read them from the index tables."""

    def delete(self, chunk_ids: Iterable[int]) -> None:
        """Remove the vectors of these chunks. An unknown ID is no error."""

    def vector_search(self, vector: Sequence[float], k: int, filter: Filter = ALL) -> list[int]: ...

    def text_search(self, query: str, k: int, filter: Filter = ALL) -> list[int]: ...

    def count(self) -> int:
        """The number of vectors in the store."""

    def close(self) -> None:
        """Release what the adapter holds. The index file stays open when the
        adapter does not own it."""
