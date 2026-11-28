"""Stream checkpoints: commit through the client, verify offline."""

from __future__ import annotations

import pytest

from anagram.local.index.local import INDEX_DB, LocalIndex
from anagram.local.sources import FolderConnector
from anagram.proofs.records import KIND_STREAM, stream_items_root
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")


class Clock:
    def __init__(self, t: float = 1_790_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    client = Client.init(tmp_path / "home", clock=clock)
    root = tmp_path / "lab"
    root.mkdir()
    (root / "notes.md").write_text("# Notes\n\nWe need statistics help.\n")
    (root / "data.csv").write_text("a,b\n1,2\n")
    index = LocalIndex.for_client(client, clock=clock)
    sid = index.add_source(FolderConnector(root))
    return client, index, sid, root, clock


def test_checkpoint_commits_and_verifies(setup):
    client, index, sid, root, clock = setup
    index.scan()
    roots = index.streams.pending(sid)
    assert len(roots) == 2
    first = index.streams.checkpoint(client, sid)
    assert first is not None
    assert first.bundle.subject.kind == KIND_STREAM
    f = first.opening.fields
    assert f["seq"] == 0 and f["prev"] is None and f["start"] == 0 and f["item_count"] == 2
    assert f["items_root"] == stream_items_root(roots).hex()
    assert f["stream_id"] == sid
    report, items_ok = index.streams.verify_checkpoint(client, sid, 0)
    assert report.ok, report.summary()
    assert items_ok
    # The log entry is a kind and a hash only.
    assert set(first.bundle.log.entry) == {"commitment", "kind", "schema"}
    assert index.streams.pending(sid) == []
    assert index.streams.checkpoint(client, sid) is None  # nothing new

    (root / "notes.md").write_text("# Notes\n\nWe need statistics help and GPU hours.\n")
    (root / "fig.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    clock.t += 3600
    index.scan()
    second = index.streams.checkpoint(client, sid)
    g = second.opening.fields
    assert g["seq"] == 1 and g["prev"] == first.root.hex() and g["start"] == 2
    assert g["item_count"] == 2
    report, items_ok = index.streams.verify_checkpoint(client, sid, 1)
    assert report.ok and items_ok
    assert [c["seq"] for c in index.streams.checkpoints(sid)] == [0, 1]
    assert second.bundle.log.tree_size > first.bundle.log.tree_size


def test_verify_detects_wrong_items(setup):
    client, index, sid, root, clock = setup
    index.scan()
    roots = index.streams.pending(sid)
    done = index.streams.checkpoint(client, sid)
    from anagram.local.index.commit import verify_stream_commit

    report, ok = verify_stream_commit(client, done.bundle, done.opening, roots[:1])
    assert report.ok and not ok


def test_checkpoint_due(setup):
    client, index, sid, root, clock = setup
    assert not index.streams.checkpoint_due(sid, 3600)  # nothing pending
    index.scan()
    assert index.streams.checkpoint_due(sid, 3600)  # never checkpointed
    index.streams.checkpoint(client, sid)
    (root / "more.txt").write_text("x")
    index.scan()
    assert not index.streams.checkpoint_due(sid, 3600)
    clock.t += 3600
    assert index.streams.checkpoint_due(sid, 3600)


def test_index_key_is_in_the_keystore_and_survives_reopen(setup, tmp_path):
    client, index, sid, root, clock = setup
    index.scan()
    index.close()
    assert client.keystore.get("index-key") is not None
    assert (client.home / INDEX_DB).exists()
    again = LocalIndex.for_client(Client(client.home, clock=clock))
    assert len(again.items(sid)) == 2
    assert len(again.streams.pending(sid)) == 2


def test_checkpoint_refuses_to_overwrite_existing_unbundled_checkpoint(setup):
    from anagram.local.index.store import dumps
    from anagram.proofs.records import Opening

    client, index, sid, root, clock = setup
    index.scan()
    existing = Opening("anagram.stream_checkpoint.v1", {"seq": 0}, {"seq": b"\xaa" * 32})
    sentinel = "01" * 32
    index.store.x(
        "INSERT INTO checkpoint (source_id, seq, root, opening, item_roots, bundle, created_at)"
        " VALUES (?, 0, ?, ?, ?, NULL, ?)",
        (sid, sentinel, dumps(existing.to_json()), dumps([]), index.now()),
    )
    with pytest.raises(RuntimeError, match="already exists"):
        index.streams.checkpoint(client, sid)
    row = index.store.one("SELECT root FROM checkpoint WHERE source_id = ? AND seq = 0", (sid,))
    assert row["root"] == sentinel
