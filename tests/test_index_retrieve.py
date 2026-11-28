"""Scoped retrieval: a hit outside the scope is never returned.

One word is planted in two spaces (a private source and a lab source). No
network; no embedder (full-text only)."""

from __future__ import annotations

import pytest
from indexkit import KEY

from anagram.local.index import retrieve
from anagram.local.index.local import LocalIndex
from anagram.local.index.spaces import PRIVATE_SCOPE, ScopeError
from anagram.local.sources import FolderConnector
from anagram.local.sources import source_state as ss

pytestmark = pytest.mark.usefixtures("no_network")

LAB = "lab:lab-0123456789abcdef"
WORD = "zymoquartz"


def _write(folder, name: str, text: str) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(text, encoding="utf-8")


@pytest.fixture
def two_spaces(tmp_path):
    mine, shared = tmp_path / "mine", tmp_path / "shared"
    _write(mine, "private-note.md", f"# Private note\n\nThe {WORD} sample is only mine.\n")
    _write(mine, "other.md", "# Other\n\nNothing about the planted word here.\n")
    _write(shared, "lab-note.md", f"# Lab note\n\nThe {WORD} run belongs to the lab.\n")
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    a = idx.add_source(FolderConnector(mine))
    b = idx.add_source(FolderConnector(shared))
    idx.scan()
    ss.set_space(idx.store, b, LAB, now=1.0)
    yield idx, a, b
    idx.close()


def _titles(hits) -> set[str]:
    return {h.title for h in hits}


def test_a_word_in_two_spaces_is_found_only_in_the_asked_space(two_spaces):
    idx, _, _ = two_spaces
    private = retrieve.search(idx, WORD, scope=PRIVATE_SCOPE)
    lab = retrieve.search(idx, WORD, scope=frozenset({LAB}))
    both = retrieve.search(idx, WORD, scope=frozenset({"private", LAB}))
    assert {h.space for h in private} == {"private"} and len(private) == 1
    assert {h.space for h in lab} == {LAB} and len(lab) == 1
    assert {h.space for h in both} == {"private", LAB}
    assert all(WORD in h.text for h in both)
    assert private[0].item_ref.startswith("item:") and private[0].kind
    assert "Private note" in _titles(private) and "Lab note" in _titles(lab)


def test_a_space_change_moves_the_hits_at_once(two_spaces):
    idx, _, b = two_spaces
    ss.set_space(idx.store, b, "private", now=2.0)
    assert {h.space for h in retrieve.search(idx, WORD, scope=PRIVATE_SCOPE)} == {"private"}
    assert len(retrieve.search(idx, WORD, scope=PRIVATE_SCOPE)) == 2
    assert retrieve.search(idx, WORD, scope=frozenset({LAB})) == []


def test_a_source_that_is_being_removed_gives_no_hit(two_spaces):
    idx, a, _ = two_spaces
    ss.get(idx.store, a, now=1.0)
    idx.store.x("UPDATE source_state SET status = ? WHERE source_id = ?", (ss.REMOVING, a))
    assert retrieve.search(idx, WORD, scope=PRIVATE_SCOPE) == []


@pytest.mark.parametrize("scope", [frozenset(), frozenset({"everything"}), frozenset({"lab"})])
def test_a_bad_scope_is_refused(two_spaces, scope):
    idx, _, _ = two_spaces
    with pytest.raises(ScopeError):
        retrieve.search(idx, WORD, scope=scope)


def test_kind_and_time_filters_and_per_item(tmp_path):
    folder = tmp_path / "notes"
    long = " ".join(
        f"Line {n} of the {WORD} log, with words to fill the chunk." for n in range(200)
    )
    _write(folder, "long.md", f"# Long\n\n{long}\n")
    _write(folder, "short.md", f"# Short\n\nOne {WORD} line.\n")
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    idx.add_source(FolderConnector(folder))
    idx.scan()
    try:
        hits = retrieve.search(idx, WORD, scope=PRIVATE_SCOPE, k=10, per_item=2)
        per = {}
        for h in hits:
            per[h.item_ref] = per.get(h.item_ref, 0) + 1
        assert max(per.values()) == 2 and len(per) == 2
        kind = hits[0].kind
        assert all(
            h.kind == kind for h in retrieve.search(idx, WORD, scope=PRIVATE_SCOPE, kinds=[kind])
        )
        assert retrieve.search(idx, WORD, scope=PRIVATE_SCOPE, since="2999-01-01") == []
        assert retrieve.search(idx, WORD, scope=PRIVATE_SCOPE, until="1970-01-02") == []
        with pytest.raises(ValueError):
            retrieve.search(idx, WORD, scope=PRIVATE_SCOPE, kinds=["poem"])
        assert retrieve.search(idx, "   ", scope=PRIVATE_SCOPE) == []
    finally:
        idx.close()


def test_the_pool_grows_when_the_scope_removes_the_first_hits(tmp_path):
    """Many lab hits rank first; the private hit is still found."""
    shared, mine = tmp_path / "shared", tmp_path / "mine"
    for n in range(30):
        _write(shared, f"lab-{n}.md", f"# Lab {n}\n\n{WORD} {WORD} {WORD} {WORD} run {n}.\n")
    _write(mine, "mine.md", f"# Mine\n\nA long text with one {WORD} in the middle of many words.\n")
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    b = idx.add_source(FolderConnector(shared))
    idx.add_source(FolderConnector(mine))
    idx.scan()
    ss.set_space(idx.store, b, LAB, now=1.0)
    try:
        # A pool of 2 holds only lab chunks; the search doubles it until the private hit comes.
        own, _ = retrieve.fused(idx, WORD, 2)
        assert len(own) == 2
        hits = retrieve.search(idx, WORD, scope=PRIVATE_SCOPE, k=1)
        assert [h.title for h in hits] == ["Mine"]
    finally:
        idx.close()


def test_hit_json_has_no_source_id_key_or_path(two_spaces):
    idx, a, b = two_spaces
    for h in retrieve.search(idx, WORD, scope=frozenset({"private", LAB})):
        data = h.json()
        text = repr(data)
        assert a not in text and b not in text and "/" not in data["item_ref"]
        assert set(data) == {
            "anchor", "item_ref", "kind", "score", "space", "text", "third_party", "time", "title", "via",
        }  # fmt: skip


def test_local_index_search_is_unchanged(two_spaces):
    idx, _, _ = two_spaces
    hits = idx.search(WORD)
    assert len(hits) == 2 and all(h.via == ("text",) for h in hits)
