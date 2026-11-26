"""Contract test of the retrieval store port (plan net 01 step 1).

One fixed query set runs against each adapter. Each answer must be the exact
top `k` of a brute-force pass (`storekit`): cosine distance for vectors, the
FTS5 BM25 score for text. A tie can come in any order.

The corpus: notes made of invented words (the porter stemmer keeps them as
they are), in two sources and two spaces, items with different times, one
item that is not present, and mail with text that other people wrote
(chunks of class `context`). Fake embedder; no network.
"""

from __future__ import annotations

import ast
import os
import random
from pathlib import Path

import pytest
from indexkit import KEY
from storekit import ExactStore, is_top_k

from anagram.local.index.local import LocalIndex
from anagram.local.index.spaces import PRIVATE
from anagram.local.index.store_port import ALL, Filter, UnsupportedFilter
from anagram.local.index.vec_store import SqliteVecStore
from anagram.local.sources import FolderConnector
from anagram.local.sources import source_state as ss
from anagram.models.embed import FakeEmbedder
from anagram.sim.writers import eml_bytes

pytestmark = pytest.mark.usefixtures("no_network")

LAB = "lab:lab-0123456789abcdef"
ME = "mira@example.org"
OTHER = "tomas@example.org"
SYL = ["ka", "zo", "mi", "ru", "ta", "lo", "vi", "na", "po", "di", "ga", "fu"]
WORDS = sorted({a + b + c for a in SYL for b in SYL for c in SYL[:4]})[:120]
SRC = Path(__file__).resolve().parents[1] / "src"


def _note(rng: random.Random) -> str:
    # Common words often, rare words seldom: a spread of BM25 scores.
    picks = [WORDS[min(int(rng.expovariate(0.06)), len(WORDS) - 1)] for _ in range(30)]
    return " ".join(picks)


def _mail(folder: Path, name: str, sender: str, body: str) -> None:
    data = eml_bytes(
        sender=("Someone", sender),
        to=("Other", OTHER if sender == ME else ME),
        subject="Run notes",
        date="Mon, 02 Nov 2026 10:00:00 +0000",
        message_id=f"<{name}@example.org>",
        body=body,
    )
    (folder / name).write_bytes(data)


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    rng = random.Random(7)  # noqa: S311 (test data)
    root = tmp_path_factory.mktemp("store-port")
    mine, shared = root / "mine", root / "shared"
    mine.mkdir()
    shared.mkdir()
    for n in range(40):
        folder = mine if n % 2 else shared
        path = folder / f"note-{n:02d}.md"
        path.write_text(f"# Note {n}\n\n{_note(rng)}\n\n{_note(rng)}\n", encoding="utf-8")
        t = 1_700_000_000 + n * 86_400 * 10  # one note each ten days
        os.utime(path, (t, t))
    for n in range(6):
        quoted = _note(rng)
        _mail(mine, f"reply-{n}.eml", ME, f"{_note(rng)}\n\nOn Mon, Tomas wrote:\n> {quoted}\n")
    idx = LocalIndex(root / "index.sqlite", KEY, owner_emails=[ME], embedder=FakeEmbedder(dim=32))
    a = idx.add_source(FolderConnector(mine))
    b = idx.add_source(FolderConnector(shared))
    idx.scan()
    # An item that is not present: its chunks are not current.
    idx.store.x("UPDATE item SET present = 0 WHERE key = 'note-03.md'")
    ss.set_space(idx.store, b, LAB, now=1.0)
    yield idx, a, b
    idx.close()


def _reference(idx: LocalIndex) -> ExactStore:
    """The brute-force adapter, with the same chunks, vectors, and filter
    fields as the index."""
    exact = ExactStore()
    emb = idx.embedder
    for table, third in (("chunk", False), ("context_chunk", True)):
        rows = idx.store.q(
            f"SELECT c.id, c.text, i.source_id, i.time, i.present, v.n,"  # noqa: S608
            " (SELECT max(n) FROM version WHERE item_id = i.id) AS last,"
            " coalesce(ss.space, 'private') AS space, coalesce(ss.status, '') AS status"
            f" FROM {table} c JOIN version v ON v.id = c.version_id"
            " JOIN item i ON i.id = v.item_id"
            " LEFT JOIN source_state ss ON ss.source_id = i.source_id"
        )
        for r in rows:
            vector = [] if third else emb.embed([r["text"]])[0]
            exact.upsert(
                r["id"],
                vector,
                {
                    "text": r["text"],
                    "space": r["space"],
                    "source_id": r["source_id"],
                    "time": r["time"],
                    "current": bool(r["present"])
                    and r["n"] == r["last"]
                    and r["status"] != ss.REMOVING,
                    "third_party": third,
                },
            )
    return exact


def _filters(a: str, b: str, idx: LocalIndex) -> list[Filter]:
    times = sorted(r[0] for r in idx.store.q("SELECT time FROM item WHERE time IS NOT NULL"))
    mid = times[len(times) // 2]
    return [
        ALL,
        Filter(spaces=frozenset({LAB})),
        Filter(spaces=frozenset({PRIVATE}), current_only=True),
        Filter(source_ids=frozenset({a})),
        Filter(since=mid),
        Filter(until=mid, current_only=True),
        Filter(spaces=frozenset()),
    ]


QUERIES = [" ".join(WORDS[i : i + 2]) for i in range(0, 60, 6)] + [WORDS[-1], "nothing"]


@pytest.fixture(scope="module")
def adapters(corpus):
    idx, _, _ = corpus
    exact = _reference(idx)
    return {"exact": exact, "sqlite_vec": SqliteVecStore(idx.store)}, exact


def test_the_corpus_has_the_cases(corpus, adapters):
    idx, _, _ = corpus
    _, exact = adapters
    own = list(exact.metas[False].values())
    assert exact.metas[True]
    assert any(not m["current"] for m in own)
    assert {m["space"] for m in own} == {PRIVATE, LAB}
    assert idx.retrieval.count() == exact.count() > 40


@pytest.mark.parametrize("name", ["exact", "sqlite_vec"])
@pytest.mark.parametrize("k", [1, 5, 25])
def test_vector_search_is_the_exact_top_k(corpus, adapters, name, k):
    idx, a, b = corpus
    stores, exact = adapters
    store = stores[name]
    for f in _filters(a, b, idx):
        for q in QUERIES:
            vec = idx.embedder.embed([q])[0]
            got = store.vector_search(vec, k, f)
            assert is_top_k(got, exact.vector_scores(vec, f), k, larger=False), (q, f)


@pytest.mark.parametrize("name", ["exact", "sqlite_vec"])
@pytest.mark.parametrize("k", [1, 5, 25])
def test_text_search_is_the_exact_top_k(corpus, adapters, name, k):
    idx, a, b = corpus
    stores, exact = adapters
    store = stores[name]
    filters = _filters(a, b, idx)
    filters += [Filter(third_party=True), Filter(third_party=True, spaces=frozenset({LAB}))]
    for f in filters:
        for q in QUERIES:
            got = store.text_search(q, k, f)
            assert is_top_k(got, exact.text_scores(q, f), k, larger=True), (q, f)


def test_context_chunks_have_no_vectors(corpus):
    idx, _, _ = corpus
    vec = idx.embedder.embed([QUERIES[0]])[0]
    assert idx.retrieval.vector_search(vec, 5, Filter(third_party=True)) == []


@pytest.mark.parametrize(
    "f", [Filter(tiers=frozenset({"discoverable"})), Filter(kinds=frozenset({"note"}))]
)
def test_a_filter_that_the_adapter_cannot_apply_is_refused(corpus, f):
    idx, _, _ = corpus
    vec = idx.embedder.embed([QUERIES[0]])[0]
    with pytest.raises(UnsupportedFilter):
        idx.retrieval.vector_search(vec, 5, f)
    with pytest.raises(UnsupportedFilter):
        idx.retrieval.text_search(QUERIES[0], 5, f)


def test_upsert_and_delete(corpus):
    idx, _, _ = corpus
    store = idx.retrieval
    cid = idx.store.one("SELECT min(id) FROM chunk WHERE embedded = 1")[0]
    vec = idx.embedder.embed([QUERIES[0]])[0]
    before = store.count()
    with idx.store.transaction():
        store.upsert(cid, vec)
    assert store.count() == before
    assert store.vector_search(vec, 1)[0] == cid
    with idx.store.transaction():
        store.delete([cid, 10**9])
    assert store.count() == before - 1
    assert cid not in store.vector_search(vec, 50)
    text = idx.store.one("SELECT text FROM chunk WHERE id = ?", (cid,))[0]
    with idx.store.transaction():  # the module corpus stays as it was
        store.upsert(cid, idx.embedder.embed([text])[0])
    assert store.count() == before


def test_no_module_outside_the_index_imports_an_adapter():
    """Callers use `LocalIndex.retrieval`; only `local/index/` makes an adapter."""
    inside = SRC / "anagram" / "local" / "index"
    bad = []
    for path in (SRC / "anagram").rglob("*.py"):
        if inside in path.parents:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            if any(n.startswith("anagram.local.index.vec_store") for n in names):
                bad.append(str(path.relative_to(SRC)))
    assert bad == []
