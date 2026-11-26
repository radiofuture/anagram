"""Google Drive source (contract v2) against `FakeGoogle`. No network.

Cases of plan R3 section 5: first sync, no change (one live call), add,
edit, delete, move out of the selection, permission lost, cursor expired
(reconcile), item too large (skipped), selection change, and scale."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from indexkit import KEY
from sourcekit import creds_for, fake_client, google_account

from anagram.identity.app.keystore import MemoryKeystore
from anagram.local.index import retention
from anagram.local.index.local import LocalIndex
from anagram.local.index.store import loads
from anagram.local.sources import connector_from_config
from anagram.local.sources import source_state as ss
from anagram.local.sources.fake_google import FakeGoogle
from anagram.local.sources.gdrive import GDOC, GSHEET, GoogleDriveConnector
from anagram.local.sources.oauth import DRIVE_SCOPE
from anagram.local.sources.sync_engine import SyncEngine

pytestmark = pytest.mark.usefixtures("no_network")


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Env:
    def __init__(self, tmp_path):
        self.fake = FakeGoogle()
        self.clock = Clock()
        self.idx = LocalIndex(tmp_path / "index.sqlite", KEY, http=self.fake, clock=self.clock)
        self.creds = creds_for(
            MemoryKeystore(), self.idx.store, self.fake, self.clock, google=fake_client(self.fake)
        )
        self.idx.credentials = self.creds
        self.acct = google_account(self.creds, self.fake, self.clock(), DRIVE_SCOPE)

    def add(self, include: dict, **cfg) -> str:
        conf = {"account": self.acct.id, "include": include, "kind": "gdrive", **cfg}
        sid = self.idx.add_source(connector_from_config(conf))
        self.idx.connectors.pop(sid)  # open again with the context of the index
        ss.ensure(self.idx.store, sid, self.clock(), account_id=self.acct.id)
        return sid

    def sync(self, sid: str):
        self.idx.connectors.pop(sid, None)
        return self.idx.scan([sid], process=False)

    def keys(self, sid: str) -> set[str]:
        rows = self.idx.store.q("SELECT key FROM item WHERE source_id = ? AND present = 1", (sid,))
        return {r["key"] for r in rows}

    def api_calls(self, start: int) -> list[str]:
        return [u for _, u in self.fake.calls[start:] if "oauth2" not in u]

    def blob(self, sid: str, key: str) -> bytes:
        row = self.idx.store.one(
            "SELECT v.blob FROM version v JOIN item i ON i.id = v.item_id"
            " WHERE i.source_id = ? AND i.key = ? ORDER BY v.n DESC LIMIT 1",
            (sid, key),
        )
        return row["blob"]


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(GoogleDriveConnector, "rate", 1e9)
    e = Env(tmp_path)
    yield e
    e.idx.close()


@pytest.fixture
def tree(env):
    f = env.fake
    lab = f.add_folder("Lab")
    sub = f.add_folder("Data", parent=lab)
    other = f.add_folder("Taxes")
    shared = f.add_drive("Group drive")
    ids = {
        "lab": lab,
        "sub": sub,
        "other": other,
        "shared": shared,
        "notes": f.add_file("notes.txt", b"Nanodisc notes.", parent=lab),
        "pdf": f.add_file("paper.pdf", b"%PDF-1.4 fake", parent=lab, mime="application/pdf"),
        "doc": f.add_file("Plan", b"# Plan\n\nThe plan.", parent=lab, mime=GDOC),
        "sheet": f.add_file("Budget", b"PK fake xlsx", parent=sub, mime=GSHEET),
        "photo": f.add_file("cat.png", b"\x89PNG fake", parent=lab, mime="image/png"),
        "tax": f.add_file("tax.txt", b"Tax.", parent=other),
        "group": f.add_file("group.txt", b"Group.", parent=shared),
    }
    return ids


def test_first_sync_reads_the_selection_newest_first(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    report = env.sync(sid)
    assert env.keys(sid) == {tree[k] for k in ("notes", "pdf", "doc", "sheet")}
    assert not report.errors
    items = {
        r["key"]: dict(r) for r in env.idx.store.q("SELECT * FROM item WHERE source_id = ?", (sid,))
    }
    doc = items[tree["doc"]]
    assert doc["name"] == "Plan.md" and doc["media_type"] == "text/markdown"
    assert doc["ref"] == f"gdrive:{tree['doc']}" and doc["kind"] == "gdrive_file"
    assert items[tree["sheet"]]["name"] == "Budget.xlsx"
    assert env.blob(sid, tree["notes"]) == b"Nanodisc notes."
    # The newest file is read first (it has the lowest item ID).
    order = [
        r["key"]
        for r in env.idx.store.q("SELECT key FROM item WHERE source_id = ? ORDER BY id", (sid,))
    ]
    assert order[0] == tree["sheet"]
    rel = {(s, d) for k, s, d in env.idx.relations("same_project")}
    assert (f"item:{doc['id']}", f"project:gdrive:{tree['lab']}") in rel
    st = ss.get(env.idx.store, sid)
    assert st.status == "live" and st.cursor["backfill"]["done"]
    extra = loads(
        env.idx.store.one("SELECT extra FROM version WHERE item_id = ?", (doc["id"],))["extra"]
    )
    assert extra["fetch"] == {"export": "text/markdown", "id": tree["doc"]}
    assert "third_party" not in extra


def test_no_change_is_one_call(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    n = len(env.fake.calls)
    report = env.sync(sid)
    calls = env.api_calls(n)
    assert len(calls) == 1 and "/drive/v3/changes?" in calls[0]
    assert not report.new and not report.changed and not report.removed
    assert ss.get(env.idx.store, sid).status == "live"


def test_add_edit_trash_delete_and_move(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    f = env.fake
    new = f.add_file("new.md", b"# New", parent=tree["sub"], mime="text/markdown")
    f.edit_file(tree["notes"], b"Nanodisc notes, second day.")
    f.trash(tree["pdf"])
    f.delete_file(tree["sheet"])
    f.move(tree["doc"], tree["other"])  # out of the selection
    f.move(tree["tax"], tree["lab"])  # into the selection
    n = len(f.calls)
    report = env.sync(sid)
    assert env.keys(sid) == {tree["notes"], new, tree["tax"]}
    assert {k for _, k in report.removed} == {tree["pdf"], tree["sheet"], tree["doc"]}
    assert {k for _, k in report.changed} == {tree["notes"]}
    assert env.blob(sid, tree["notes"]) == b"Nanodisc notes, second day."
    assert sum("/drive/v3/changes?" in u for u in env.api_calls(n)) == 1


def test_folder_moves_and_trash(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    f = env.fake
    f.move(tree["other"], tree["lab"])  # a folder moves into the selection
    env.sync(sid)
    assert tree["tax"] in env.keys(sid)
    f.trash(tree["sub"])  # a folder in the selection goes to the trash
    env.sync(sid)
    assert tree["sheet"] not in env.keys(sid)
    f.move(tree["other"], f.root_id)  # and out again
    env.sync(sid)
    assert tree["tax"] not in env.keys(sid)


def test_shared_drive_and_my_drive(env, tree):
    sid = env.add({"shared_drives": [tree["shared"]]})
    env.sync(sid)
    assert env.keys(sid) == {tree["group"]}
    sid2 = env.add({"my_drive": True})
    env.sync(sid2)
    assert env.keys(sid2) == {tree[k] for k in ("notes", "pdf", "doc", "sheet", "tax")}
    rel = {d for _, _, d in env.idx.relations("same_project")}
    assert "project:gdrive:my_drive" in rel and f"project:gdrive:{tree['shared']}" in rel


def test_types_all_and_size_limit_and_no_download(env, tree):
    f = env.fake
    f.add_file(
        "big.pdf", b"%PDF" + b"x" * (2 * 1024 * 1024), parent=tree["lab"], mime="application/pdf"
    )
    locked = f.add_file("locked.txt", b"No.", parent=tree["lab"], can_download=False)
    sid = env.add({"folders": [tree["lab"]]}, types="all", max_mb=1)
    env.sync(sid)
    assert tree["photo"] in env.keys(sid)
    assert locked not in env.keys(sid)
    st = ss.get(env.idx.store, sid)
    assert st.skipped == 2


def test_markdown_export_falls_back_to_text(env, tree):
    env.fake.markdown_export = False
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    row = env.idx.store.one("SELECT name, media_type FROM item WHERE key = ?", (tree["doc"],))
    assert (row["name"], row["media_type"]) == ("Plan.txt", "text/plain")


def test_third_party_owner_is_marked(env, tree):
    other = env.fake.add_file(
        "theirs.txt", b"Their text.", parent=tree["lab"], owner="peer@example.org"
    )
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    row = env.idx.store.one(
        "SELECT v.extra FROM version v JOIN item i ON i.id = v.item_id WHERE i.key = ?", (other,)
    )
    assert loads(row["extra"])["third_party"] is True


def test_permission_lost_and_sign_in_needed(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    env.fake.fail_next(403, body=None, times=1)
    env.sync(sid)
    st = ss.get(env.idx.store, sid)
    assert (st.status, st.error_code) == ("attention", "permission_lost")
    ss.clear_fault(env.idx.store, sid, now=env.clock())
    env.fake.revoke_grant()
    env.sync(sid)
    st = ss.get(env.idx.store, sid)
    assert (st.status, st.error_code) == ("attention", "auth_expired")
    assert env.creds.account(env.acct.id).status == "expired"
    assert len(env.keys(sid)) == 4  # a fault deletes nothing


def test_rate_limit_waits_with_a_time(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    env.fake.fail_next(429, headers={"retry-after": "120"})
    env.sync(sid)
    st = ss.get(env.idx.store, sid)
    assert (st.status, st.error_code) == ("waiting", "rate_limited")
    assert st.next_at > env.clock()


def test_cursor_expired_gives_a_reconcile(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    env.fake.expire_changes()
    del env.fake.files[tree["pdf"]]  # gone with no change that the source can read
    added = env.fake.add_file("late.txt", b"Late.", parent=tree["lab"])
    env.sync(sid)
    assert env.keys(sid) == {tree["notes"], tree["doc"], tree["sheet"], added}
    st = ss.get(env.idx.store, sid)
    assert st.error_code is None and st.cursor["backfill"]["done"]
    assert "seen" not in st.cursor
    n = len(env.fake.calls)
    env.sync(sid)
    assert len(env.api_calls(n)) == 1


def test_selection_change_reads_again_and_deletes(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    conn = connector_from_config(
        {**env.idx.source(sid)["config"], "include": {"folders": [tree["sub"], tree["other"]]}}
    )
    env.idx.set_source_config(sid, conn.config())
    ss.set_cursor(env.idx.store, sid, {"reset": True}, now=env.clock())
    env.sync(sid)
    assert env.keys(sid) == {tree["sheet"], tree["tax"]}


def test_large_binary_blob_is_dropped_and_read_again(env, tree):
    data = b"%PDF-1.4 " + bytes(range(256)) * 5000
    big = env.fake.add_file("big.pdf", data, parent=tree["lab"], mime="application/pdf")
    sid = env.add({"folders": [tree["lab"]]})
    env.sync(sid)
    vid = env.idx.store.one(
        "SELECT v.id FROM version v JOIN item i ON i.id = v.item_id WHERE i.key = ?", (big,)
    )["id"]
    assert retention.after_convert(env.idx, vid) is True
    v = env.idx.store.one(
        "SELECT v.*, i.key, i.source_id AS sid FROM version v JOIN item i ON i.id = v.item_id"
        " WHERE v.id = ?",
        (vid,),
    )
    assert v["blob"] is None
    assert retention.refetch(env.idx, v) == data
    # An export keeps its bytes: it is not byte-stable.
    doc_vid = env.idx.store.one(
        "SELECT v.id FROM version v JOIN item i ON i.id = v.item_id WHERE i.key = ?", (tree["doc"],)
    )["id"]
    env.idx.store.x("UPDATE version SET blob = ? WHERE id = ?", (b"x" * (2 << 20), doc_vid))
    assert retention.after_convert(env.idx, doc_vid) is False


def test_choices_and_preview(env, tree):
    cls = GoogleDriveConnector
    from anagram.local.sources.base import SourceContext

    ctx = SourceContext(http=env.fake, credentials=env.creds)
    top = cls.choices(ctx, env.acct, None)["items"]
    assert [(i["type"], i["name"]) for i in top] == [
        ("my_drive", "My Drive"),
        ("shared_drive", "Group drive"),
    ]
    names = {i["name"] for i in cls.choices(ctx, env.acct, "my_drive")["items"]}
    assert names == {"Lab", "Taxes"}
    assert [i["name"] for i in cls.choices(ctx, env.acct, tree["lab"])["items"]] == ["Data"]
    assert cls.preview(ctx, {}) == {"estimate": None, "of": None}


def test_config_has_no_secret_and_checks_include(env, tree):
    sid = env.add({"folders": [tree["lab"]]})
    cfg = env.idx.source(sid)["config"]
    assert set(cfg) == {"account", "include", "kind", "max_mb", "types"}
    from anagram.local.sources.base import ConnectorError

    for bad in ({}, {"folders": "x"}, {"folders": [1]}):
        with pytest.raises(ConnectorError):
            GoogleDriveConnector("a", bad)


def test_fake_gives_the_documented_shapes(env, tree):
    """Each key of the documented shapes is in the answer of the fake."""
    shapes = json.loads((Path(__file__).parent / "fixtures/sources/google/drive.json").read_text())
    tok = env.creds.auth_headers(env.acct.id, "https://www.googleapis.com/drive/v3/files")
    base = "https://www.googleapis.com/drive/v3"

    def get(path):
        return env.fake("GET", base + path, tok, None).json()

    start = get("/changes/startPageToken")
    assert set(shapes["start_page_token"]) <= set(start)
    files = get("/files?q=trashed%3Dfalse&pageSize=1&orderBy=modifiedTime+desc")
    assert set(shapes["files_list"]) <= set(files)
    doc = get(f"/files/{tree['doc']}")
    assert set(shapes["files_list"]["files"][0]) - {"owners"} <= set(doc)
    changes = get(f"/changes?pageToken={start['startPageToken'].split('.')[0]}.1")
    assert set(shapes["changes_list"]) - {"newStartPageToken"} <= set(changes)
    assert set(shapes["changes_list"]["changes"][0]) <= set(changes["changes"][0])
    assert set(shapes["drives_list"]) <= set(get("/drives"))
    from anagram.local.sources.google import classify_google
    from anagram.local.sources.http import HttpResponse

    rate = HttpResponse(403, {}, json.dumps(shapes["error_403_rate"]).encode())
    assert classify_google(rate) == "retry"


def test_scale_50000_files(env, monkeypatch):
    """50 000 files: 50 list calls for the backfill, at most 200 upserts
    between two cursors, and one call for the next sync. `_apply_item` is a
    stub, so the test measures the source and the engine only."""
    f = env.fake
    lab = f.add_folder("Lab")
    for i in range(50_000):
        f.add_file(f"n{i}.txt", b"x", parent=lab)
    peak = []
    real_commit = SyncEngine._commit

    def commit(self, sid, src, pending, cursor, note, result, report):
        peak.append(len(pending))
        return real_commit(self, sid, src, [], cursor, note, result, report)

    monkeypatch.setattr(SyncEngine, "_commit", commit)
    sid = env.add({"folders": [lab]})
    n = len(f.calls)
    t0 = time.monotonic()
    env.sync(sid)
    assert time.monotonic() - t0 < 30
    calls = env.api_calls(n)
    lists = [u for u in calls if "/drive/v3/files?" in u and "mimeType%21%3D" in u]
    assert len(lists) == 50
    assert max(peak) <= 200
    assert ss.get(env.idx.store, sid).cursor["backfill"]["done"]
    n = len(f.calls)
    env.sync(sid)
    assert len(env.api_calls(n)) == 1


def test_end_to_end_5000_files_with_the_real_store(env):
    f = env.fake
    lab = f.add_folder("Lab")
    for i in range(5_000):
        f.add_file(f"n{i}.txt", f"note {i}".encode(), parent=lab)
    sid = env.add({"folders": [lab]})
    env.sync(sid)
    assert len(env.keys(sid)) == 5_000
    n = len(f.calls)
    env.sync(sid)
    assert len(env.api_calls(n)) == 1
