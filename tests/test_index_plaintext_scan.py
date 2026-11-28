"""No plaintext of the index on disk, including temp files.

The index holds notes with canary words and dense vectors. A load that can
make SQLite use temp space runs (searches, a large sort, GROUP BY, an FTS5
merge, VACUUM) while `FdWatch` reads each file that the process holds open
outside the store and the notes. Then the store folder and the OS temp
folders are scanned. Each scan must find 0 canary words and 0 vector runs.
A plaintext control file shows that the scan finds what is there.

SQLCipher does not encrypt SQLite temp files. The control test sets
`temp_store = FILE` and shows that the watch then finds plaintext temp files
(`etilqs_*`, deleted at open). The index store sets `temp_store = MEMORY`.

The proofs do not depend on time: the watch polls from the SQLite progress
handler of the connection (inside each statement, while its temp files are
open), and the test of a deleted file polls while the file is open. A busy
machine makes the tests slower, not different.
"""

from __future__ import annotations

import hashlib
import os
import random
import tempfile
import time
from collections.abc import Sequence

import pytest
import sqlcipher3
from indexkit import KEY

from anagram.local.index import retrieve
from anagram.local.index.local import LocalIndex
from anagram.local.index.spaces import PRIVATE_SCOPE
from anagram.local.sources import FolderConnector
from anagram.models.embed import Embedder
from anagram.sim.plaintext_scan import (
    FdWatch,
    float32_needles,
    scan,
    temp_roots,
    text_needles,
)

pytestmark = pytest.mark.usefixtures("no_network")

PROGRESS_STEPS = 20_000  # SQLite VM steps between two polls of the watch
CANARIES = [f"qxcanary{hashlib.sha256(str(i).encode()).hexdigest()[:16]}" for i in range(5)]


class DenseEmbedder(Embedder):
    """A dense unit vector from a hash of the text: each value is nonzero, so
    a run of float32 bytes is unique."""

    name = "dense-fake"

    def __init__(self, dim: int = 48) -> None:
        self.dim = dim

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        out = []
        for t in texts:
            rng = random.Random(hashlib.sha256(t.encode()).digest())  # noqa: S311 (test data)
            v = [rng.uniform(0.1, 1.0) * rng.choice((-1, 1)) for _ in range(self.dim)]
            n = sum(x * x for x in v) ** 0.5
            out.append([x / n for x in v])
        return out


def test_the_index_leaves_no_plaintext_on_disk(tmp_path):
    notes, store = tmp_path / "notes", tmp_path / "store"
    notes.mkdir()
    store.mkdir()
    filler = "membrane transport assay buffer ladder gel lane voltage sample " * 6
    for i, word in enumerate(CANARIES):
        (notes / f"n{i}.md").write_text(f"# Note {i}\n\n{filler} {word} {filler}\n")
    for i in range(40):
        (notes / f"f{i}.md").write_text(f"# Filler {i}\n\n{filler} run {i}\n")
    emb = DenseEmbedder()
    start = time.time() - 1
    idx = LocalIndex(store / "index.sqlite", KEY, embedder=emb)
    assert idx.store.one("PRAGMA temp_store")[0] == 2  # MEMORY
    needles = text_needles(CANARIES)
    with FdWatch(needles + float32_needles([]), allowed=[store, notes]) as watch:
        # A poll each PROGRESS_STEPS SQLite steps, inside each statement.
        idx.store._db.set_progress_handler(watch.progress, PROGRESS_STEPS)
        idx.add_source(FolderConnector(notes))
        idx.scan()
        rows = idx.store.q(
            "SELECT text FROM chunk WHERE " + " OR ".join("text LIKE ?" for _ in CANARIES),  # noqa: S608
            [f"%{w}%" for w in CANARIES],
        )
        vectors = emb.embed([r[0] for r in rows])
        watch.needles += float32_needles(vectors)
        for word in CANARIES:
            assert retrieve.search(idx, f"{word} gel", scope=PRIVATE_SCOPE)
        idx.store.q("SELECT text FROM chunk ORDER BY text DESC")
        idx.store.q("SELECT DISTINCT text FROM chunk")
        idx.store.q("SELECT anchor, count(*), max(text) FROM chunk GROUP BY anchor")
        idx.store.x("INSERT INTO chunk_fts (chunk_fts) VALUES ('optimize')")
        idx.store.x("VACUUM")
        idx.store._db.set_progress_handler(None, 0)
    idx.close()
    needles = watch.needles
    assert len(needles) >= len(CANARIES) + 2 * len(CANARIES)
    assert watch.hooked > 2  # the watch ran inside the statements of the load
    assert watch.plaintext() == []
    assert scan([store], needles) == []
    assert scan(temp_roots(), needles, since=start, skip=[notes]) == []
    # The control: the scan finds plaintext that is there.
    control = tmp_path / "control"
    control.mkdir()
    (control / "plain.bin").write_bytes(b"x" * 5000 + needles[0] + needles[-1] + b"y" * 10)
    assert {h.needle for h in scan([control], needles)} == {0, len(needles) - 1}


def test_fdwatch_reads_a_temp_file_that_is_deleted_at_once(tmp_path):
    secret = text_needles(["qxcanarytempfile0001"])
    with FdWatch(secret, thread=False) as watch:
        with tempfile.TemporaryFile(dir=tmp_path) as f:  # unlinked at open on POSIX
            f.write(b"head " + secret[0] + b" tail")
            f.flush()
            watch.poll()  # the file is open and holds the secret now
    found = watch.plaintext()
    assert found and found[0].hits == {0}
    assert os.name != "posix" or found[0].deleted


def test_the_watch_finds_plaintext_temp_files_of_sqlcipher(tmp_path):
    """The control: with `temp_store = FILE`, a large sort writes plaintext
    to a temp file. So `temp_store = MEMORY` in the index store matters."""
    word = "qxcanarysortrow"
    db = sqlcipher3.connect(str(tmp_path / "x.db"), isolation_level=None)
    db.execute(f"PRAGMA key = \"x'{KEY.hex()}'\"")
    db.execute("PRAGMA cache_size = -1000")
    db.execute("PRAGMA temp_store = FILE")
    db.execute("CREATE TABLE t (x TEXT)")
    db.execute("BEGIN")
    db.executemany(
        "INSERT INTO t VALUES (?)", [(f"{word}{i:06d} " + "pad" * 100,) for i in range(20_000)]
    )
    db.execute("COMMIT")
    with FdWatch(text_needles([word]), allowed=[tmp_path], thread=False) as watch:
        db.set_progress_handler(watch.progress, PROGRESS_STEPS)
        db.execute("SELECT x FROM t ORDER BY x DESC").fetchall()
        db.set_progress_handler(None, 0)
    db.close()
    assert watch.hooked > 2
    assert any(f.deleted for f in watch.plaintext())
