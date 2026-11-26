"""The index store is one encrypted SQLCipher file. It has no plaintext."""

from __future__ import annotations

import pytest
from indexkit import KEY, lab, lab_index

from anagram.local.index.store import CACHE_MB, IndexStore, IndexStoreError

pytestmark = pytest.mark.usefixtures("no_network")


def _db_bytes(path) -> bytes:
    data = path.read_bytes()
    for extra in ("-journal", "-wal"):
        p = path.with_name(path.name + extra)
        if p.exists():
            data += p.read_bytes()
    return data


def test_no_canary_or_text_in_index_db(sim_community, tmp_path):
    sim = sim_community
    db = tmp_path / "chen.sqlite"
    chen = lab(sim, "chen")
    index, _ = lab_index(db, sim.out_dir / chen["path"])
    index.scan()
    # The index really holds the canaries (in its documents and chunks).
    texts = []
    for it in index.items():
        m = index.meaning(it.source_id, it.key)
        texts.append(m.extracted.text + m.extracted.quoted + str(m.extracted.meta))
    blob = "\n".join(texts)
    lab_canaries = [c["canary"] for c in sim.canaries if c["lab_id"] == chen["id"]]
    assert sum(c in blob for c in lab_canaries) >= len(lab_canaries) - 1  # all but the raw file
    assert index.search("cryo")  # full-text search works on the encrypted file
    index.close()

    raw = _db_bytes(db)
    assert not raw.startswith(b"SQLite format 3")
    for c in lab_canaries:
        assert c.encode() not in raw
    # No file names, chip IDs, labels, summaries, or table names either.
    for probe in (
        b"zotero-export",
        b"collaborator-thread",
        b"NbT7",
        b"anagram:affinity-prediction",
        b"openalex:",
        b"Binding-affinity",
        b"Krios",
        b"mchen@",
        b"chunk_fts",
        b"CREATE TABLE",
    ):
        assert probe not in raw, probe


def test_wrong_key_is_refused(tmp_path):
    db = tmp_path / "i.sqlite"
    s = IndexStore(db, KEY)
    s.set_meta("x", {"text": "secret"})
    s.close()
    with pytest.raises(IndexStoreError):
        IndexStore(db, bytes(32))
    with pytest.raises(IndexStoreError):
        IndexStore(tmp_path / "j.sqlite", b"short")
    assert IndexStore(db, KEY).get_meta("x") == {"text": "secret"}


def test_changed_page_is_refused(tmp_path):
    db = tmp_path / "i.sqlite"
    s = IndexStore(db, KEY)
    s.set_meta("x", "secret")
    s.close()
    data = bytearray(db.read_bytes())
    data[100] ^= 0x01  # inside page 1 (after the 16-byte salt)
    db.write_bytes(bytes(data))
    with pytest.raises(IndexStoreError):
        IndexStore(db, KEY)


def test_the_page_cache_holds_the_vector_pages(tmp_path):
    """Plan net 01 finding 1: SQLCipher decrypts a page again each time it
    leaves the cache, so the cache must hold the vector pages (512 MB limit;
    only read pages use RAM). Temp files stay in RAM (no plaintext)."""
    s = IndexStore(tmp_path / "i.sqlite", KEY)
    try:
        assert s.one("PRAGMA cache_size")[0] == -CACHE_MB * 1024
        assert CACHE_MB >= 512
        assert s.one("PRAGMA temp_store")[0] == 2
    finally:
        s.close()
