"""The lab space in the local index (plan R2, step S7): the `labspace`
source, publish from a source in a lab space, withdraw, and the `own` guards
(no lab item in a checkpoint, a finding draft, or a brief)."""

from __future__ import annotations

import pytest

from anagram.local.api import lens_items
from anagram.local.index import spaces
from anagram.local.index.local import LocalIndex
from anagram.local.sources import SOURCES, FolderConnector, source_state
from anagram.local.understanding import kinds
from anagram.local.understanding.drafts import draft_findings
from anagram.network.groups.app import labspace
from anagram.network.groups.app.labrecords import LabItemDraft
from anagram.network.groups.app.labroster import LabError

ORIGIN = {"source_kind": "folder", "name": "notes.md", "media_type": "text/markdown"}
FINDING = "# Zebrafish result\n\nWe found that zebrafish fins regrow in 7 days at 28 C.\n"


@pytest.fixture
def pair(net, tmp_path):
    """A lab with a PI (A) and a member (B), and an index for each."""
    a, b = (net.join(tmp_path / n, f"fake-{n}").client for n in ("ix-a", "ix-b"))
    lab_id = a.labs.lab_create("Index Lab")["lab_id"]
    a.labs.lab_add(lab_id, b.device.subject)
    b.labs.lab_sync(lab_id)
    ia, ib = LocalIndex.for_client(a), LocalIndex.for_client(b)
    yield lab_id, a, b, ia, ib
    ia.close()
    ib.close()


def _hits(idx: LocalIndex, q: str) -> list:
    return idx.search(q, k=20)


def test_the_composition_gives_the_kind_and_it_is_not_own(pair):
    """The `Client` composition gives the lab space kind to its index; the
    registry of the app (L2) does not have it."""
    _, _, _, ia, _ = pair
    assert ia.kinds.get("labspace") is labspace.LabSpaceConnector
    assert SOURCES.get("labspace") is None
    assert labspace.LabSpaceConnector.own is False


def test_member_finds_an_item_of_another_member(pair):
    lab_id, a, b, _, ib = pair
    item_id = a.lab_space.lab_publish(
        lab_id,
        LabItemDraft(
            kind="note",
            title="Fin regrowth",
            text=FINDING,
            origin=ORIGIN,
            type="finding",
            facts=({"kind": "claim", "value": "Fins regrow in 7 days.", "score": 900},),
        ),
    )
    b.labs.lab_sync(lab_id)
    out = labspace.sync_index(b.lab_context, ib)
    [sid] = out["sources"]
    assert ib.source(sid)["kind"] == "labspace"
    assert ib.source(sid)["label"] == "Index Lab"
    assert spaces.space_of(ib, sid) == spaces.lab_space(lab_id)
    assert spaces.lab_space(lab_id) in spaces.readable_spaces(b.lab_context)
    hits = _hits(ib, "zebrafish regrow")
    assert hits and {h.source_id for h in hits} == {sid}
    assert hits[0].key == item_id and hits[0].name == "Fin regrowth"
    # The author's kind and facts come with the item (no model call again).
    vid = ib.store.one("SELECT id FROM version WHERE source_id = ?", (sid,))[0]
    k = kinds.kind_of(ib, vid)
    assert (k.kind, k.by) == ("finding", "lab")
    claims = [f for f in ib.facts(sid, item_id, "claim") if f.data.get("by") == "lab"]
    assert claims and claims[0].score == pytest.approx(0.9)
    # Safe to run again: no second source, no new version.
    assert labspace.sync_index(b.lab_context, ib)["sources"] == [sid]
    assert ib.store.one("SELECT count(*) FROM version WHERE source_id = ?", (sid,))[0] == 1

    # A removed item stops to show.
    a.lab_space.lab_unpublish(lab_id, item_id)
    b.labs.lab_sync(lab_id)
    labspace.sync_index(b.lab_context, ib)
    assert _hits(ib, "zebrafish regrow") == []


def test_a_lab_item_is_in_no_checkpoint_draft_or_lens_item(pair):
    lab_id, a, b, _, ib = pair
    a.lab_space.lab_publish(
        lab_id, LabItemDraft(kind="note", title="Fin", text=FINDING, origin=ORIGIN, type="finding")
    )
    b.labs.lab_sync(lab_id)
    [sid] = labspace.sync_index(b.lab_context, ib)["sources"]
    assert _hits(ib, "zebrafish")
    assert ib.is_own(sid) is False and sid not in ib.own_sources()
    assert ib.items(own_only=True) == []
    assert ib.streams.checkpoint(b, sid) is None
    assert draft_findings(ib) == []
    assert lens_items(ib) == []  # the input of the matching lines draft
    # A lab item never goes back into the lab space.
    key = ib.items(sid)[0].key
    with pytest.raises(LabError, match="lab space already"):
        labspace.publish_index_item(b.lab_context, ib, lab_id, sid, key)


def _folder(tmp_path, name="results"):
    root = tmp_path / name
    root.mkdir()
    (root / "fins.md").write_text(FINDING)
    return root


def test_a_source_in_the_lab_space_publishes_and_withdraws(pair, tmp_path):
    lab_id, a, b, ia, ib = pair
    root = _folder(tmp_path)
    src = ia.add_source(FolderConnector(root))
    ia.scan()
    space = spaces.lab_space(lab_id)
    source_state.set_space(
        ia.store, src, space, now=ia.clock(), hooks=(labspace.space_hook(a.lab_context, ia),)
    )
    [row] = a.lab_roster.labcache.published_rows(lab_id)
    assert row["source_id"] == src and row["auto"] is True and row["version_n"] == 1
    # The lab item has no path and no source ID.
    item = a.lab_space.lab_item(lab_id, row["item_id"])["item"]
    assert item["kind"] == "source_item" and item["origin"]["name"] == "fins.md"
    assert src not in str(item) and str(root) not in str(item)

    # The author sees the item one time (the original in the folder source).
    [lab_sid] = labspace.sync_index(a.lab_context, ia)["sources"]
    assert {h.source_id for h in _hits(ia, "zebrafish")} == {src}
    assert ia.items(lab_sid) == []

    # The other member finds it.
    b.labs.lab_sync(lab_id)
    labspace.sync_index(b.lab_context, ib)
    assert len(_hits(ib, "zebrafish")) == 1

    # A new version of the file gives a new revision of the same lab item.
    (root / "fins.md").write_text(FINDING + "\nAlso at 25 C, in 9 days.\n")
    ia.scan()
    assert labspace.publish_pending(a.lab_context, ia, lab_id, src) == 1
    assert labspace.publish_pending(a.lab_context, ia, lab_id, src) == 0  # idempotent
    assert a.lab_space.lab_item(lab_id, row["item_id"])["item"]["rev"] == 2
    b.labs.lab_sync(lab_id)
    labspace.sync_index(b.lab_context, ib)
    assert [h.text for h in _hits(ib, "9 days")]

    # Back to private: the item goes from the lab space.
    source_state.set_space(
        ia.store,
        src,
        spaces.PRIVATE,
        now=ia.clock(),
        hooks=(labspace.space_hook(a.lab_context, ia),),
    )
    assert a.lab_roster.labcache.published_rows(lab_id) == []
    b.labs.lab_sync(lab_id)
    labspace.sync_index(b.lab_context, ib)
    assert _hits(ib, "zebrafish") == []
    assert _hits(ia, "zebrafish")  # the original stays private


def test_with_no_hook_the_sync_does_the_work(pair, tmp_path):
    lab_id, a, b, ia, ib = pair
    src = ia.add_source(FolderConnector(_folder(tmp_path)))
    ia.scan()
    source_state.set_space(ia.store, src, spaces.lab_space(lab_id), now=ia.clock())
    assert a.lab_roster.labcache.published_rows(lab_id) == []  # the hook had no client
    out = labspace.sync_index(a.lab_context, ia)
    assert out["published"] == 1
    # A removed source: its items go from the lab space at the next sync.
    from anagram.local.index import retention

    retention.remove_source(ia, src)
    assert labspace.sync_index(a.lab_context, ia)["withdrawn"] == 1
    b.labs.lab_sync(lab_id)
    labspace.sync_index(b.lab_context, ib)
    assert _hits(ib, "zebrafish") == []


def test_an_item_put_in_by_hand_stays(pair, tmp_path):
    lab_id, a, b, ia, ib = pair
    src = ia.add_source(FolderConnector(_folder(tmp_path)))
    ia.scan()
    key = ia.items(src)[0].key
    item_id = labspace.publish_index_item(a.lab_context, ia, lab_id, src, key)
    assert labspace.publish_index_item(a.lab_context, ia, lab_id, src, key) == item_id  # idempotent
    assert labspace.sync_index(a.lab_context, ia)["withdrawn"] == 0
    assert a.lab_space.lab_items(lab_id)[0]["item_id"] == item_id
    # The source is private, so the lab copy shows in the lab space source.
    [lab_sid] = labspace.sync_index(a.lab_context, ia)["sources"]
    assert [i.key for i in ia.items(lab_sid)] == [item_id]


def test_mail_and_files_do_not_go_into_the_lab_space(pair):
    lab_id, a, _, ia, _ = pair
    ia.store.x(
        "INSERT INTO source (id, kind, label, config, created_at, prefs)"
        " VALUES (?, 'gmail', 'Mail', '{\"kind\": \"gmail\"}', '2026-11-16T00:00:00Z', '{}')",
        ("ab" * 16,),
    )
    with pytest.raises(LabError, match="Mail"):
        labspace.publish_index_item(a.lab_context, ia, lab_id, "ab" * 16, "k")
    source_state.set_space(ia.store, "ab" * 16, spaces.lab_space(lab_id), now=ia.clock())
    assert labspace.publish_pending(a.lab_context, ia, lab_id, "ab" * 16) == 0
    with pytest.raises(LabError, match="not on this computer"):
        labspace.publish_index_item(a.lab_context, ia, lab_id, "cd" * 16, "k")


def test_leave_drops_the_source(pair):
    lab_id, a, b, _, ib = pair
    a.lab_space.lab_publish(
        lab_id, LabItemDraft(kind="note", title="Fin", text=FINDING, origin=ORIGIN)
    )
    b.labs.lab_sync(lab_id)
    [sid] = labspace.sync_index(b.lab_context, ib)["sources"]
    assert _hits(ib, "zebrafish")
    b.labs.lab_leave(lab_id)
    assert labspace.sync_index(b.lab_context, ib)["sources"] == []
    assert sid not in ib.sources() and _hits(ib, "zebrafish") == []


def test_removed_member_loses_the_source(pair):
    lab_id, a, b, _, ib = pair
    a.lab_space.lab_publish(
        lab_id, LabItemDraft(kind="note", title="Fin", text=FINDING, origin=ORIGIN)
    )
    b.labs.lab_sync(lab_id)
    labspace.sync_index(b.lab_context, ib)
    a.labs.lab_remove(lab_id, b.device.subject)
    b.labs.lab_sync()
    assert labspace.sync_index(b.lab_context, ib)["sources"] == []
    assert _hits(ib, "zebrafish") == []


def test_a_fresh_index_opens_the_source_from_its_config(pair):
    lab_id, a, b, _, ib = pair
    a.lab_space.lab_publish(
        lab_id, LabItemDraft(kind="note", title="Fin", text=FINDING, origin=ORIGIN)
    )
    b.labs.lab_sync(lab_id)
    [sid] = labspace.sync_index(b.lab_context, ib, scan=False)["sources"]
    again = LocalIndex.for_client(b)  # as the helper thread opens it
    try:
        assert again.source(sid)["config"] == {"kind": "labspace", "lab_id": lab_id}
        report = again.scan([sid])
        assert report.errors == [] and len(report.new) == 1
        assert _hits(again, "zebrafish")
    finally:
        again.close()
