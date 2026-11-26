"""Byte retention and source removal (`local/index/retention.py`), and the route
`DELETE /api/sources/{id}`. No network."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import ClassVar

import pytest
from indexkit import KEY
from test_ui_api import ORIGIN
from test_ui_sources_api import add, events, member, places  # noqa: F401 - fixtures

from anagram.local.index import jobs, retention
from anagram.local.index.local import LocalIndex
from anagram.local.index.media import sniff_bytes
from anagram.local.sources import SOURCES, FolderConnector
from anagram.local.sources import source_state as ss
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
)
from anagram.local.sources.http import SourceFault
from anagram.local.sources.sync import Cursor, Upsert

pytestmark = pytest.mark.usefixtures("no_network")

BIG = retention.KEEP_BLOB_MAX + 10


def big_text(word: str) -> bytes:
    return (f"# {word}\n\n" + f"{word} line.\n" * (BIG // 8)).encode()


class CloudToy(Connector):
    """A v2 source with bytes that it can give again (as Drive files)."""

    kind = "cloud_toy"
    auth: ClassVar[str] = "none"
    refetchable: ClassVar[bool] = True
    files: ClassVar[dict[str, bytes]] = {}
    fetched: ClassVar[list[str]] = []

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> CloudToy:
        return cls()

    def config(self) -> dict:
        return {"kind": self.kind}

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        raise ConnectorError("use sync")

    def sync(self, ctx):
        from anagram.core.crypto.chunked import hash_bytes

        for key, data in sorted(self.files.items()):
            yield Upsert(
                EvidenceItem(
                    key=key,
                    kind="cloud_file",
                    name=key,
                    media_type=sniff_bytes(data, key),
                    digest=hash_bytes(data),
                    ref=f"cloud:{key}",
                    data=data,
                    extra={"fetch": {"id": key}},
                )
            )
        yield Cursor({"done": True})

    def fetch(self, key: str, extra: dict) -> bytes:
        type(self).fetched.append(key)
        if key not in self.files:
            raise SourceFault("not_found", status=404)
        return self.files[key]


@pytest.fixture(autouse=True)
def cloud():
    CloudToy.files, CloudToy.fetched = {}, []
    SOURCES.register(CloudToy.kind, CloudToy)
    yield CloudToy
    SOURCES.unregister(CloudToy.kind)


@pytest.fixture
def index(tmp_path):
    idx = LocalIndex(tmp_path / "index.sqlite", KEY)
    yield idx
    idx.close()


def rows_of(index, sid: str) -> dict[str, int]:
    """The number of rows of one source in each table."""
    s = index.store
    vids = "SELECT id FROM version WHERE source_id = ?"
    items = "SELECT 'item:' || id FROM item WHERE source_id = ?"
    q = {
        "source": ("SELECT count(*) FROM source WHERE id = ?", 1),
        "source_state": ("SELECT count(*) FROM source_state WHERE source_id = ?", 1),
        "item": ("SELECT count(*) FROM item WHERE source_id = ?", 1),
        "version": ("SELECT count(*) FROM version WHERE source_id = ?", 1),
        "job": ("SELECT count(*) FROM job WHERE source_id = ?", 1),
        "checkpoint": ("SELECT count(*) FROM checkpoint WHERE source_id = ?", 1),
        "document": (f"SELECT count(*) FROM document WHERE version_id IN ({vids})", 1),  # noqa: S608
        "chunk": (f"SELECT count(*) FROM chunk WHERE version_id IN ({vids})", 1),  # noqa: S608
        "fact": (f"SELECT count(*) FROM fact WHERE version_id IN ({vids})", 1),  # noqa: S608
        "relation": (
            f"SELECT count(*) FROM relation WHERE src IN ({items}) OR dst IN ({items})",  # noqa: S608
            2,
        ),
    }
    return {name: s.one(sql, (sid,) * n)[0] for name, (sql, n) in q.items()}


# ---------------------------------------------------------------- retention


def test_large_cloud_blob_is_dropped_after_conversion_and_read_again(index, cloud):
    cloud.files = {"big.md": big_text("alpha"), "small.md": b"# Small\n\nbeta text\n"}
    sid = index.add_source(CloudToy())
    index.scan([sid])
    blobs = dict(
        index.store.q(
            "SELECT i.key, length(v.blob) FROM version v JOIN item i ON i.id = v.item_id"
            " WHERE v.source_id = ?",
            (sid,),
        )
    )
    assert blobs == {"big.md": None, "small.md": len(cloud.files["small.md"])}
    assert index.search("alpha")[0].key == "big.md"  # converted before the drop
    vid = index.store.one("SELECT id FROM version WHERE blob IS NULL")[0]
    # A new conversion (for example a new converter) gets the bytes again.
    jobs.enqueue(index.store, jobs.CONVERT, vid, sid, index.clock(), reset=True)
    assert index.jobs.run().done >= 1
    assert cloud.fetched == ["big.md"]
    # The source changed the bytes: a skipped item, with the reason.
    cloud.files["big.md"] = big_text("gamma")
    jobs.enqueue(index.store, jobs.CONVERT, vid, sid, index.clock(), reset=True)
    index.jobs.run()
    reasons = [s.reason for s in index.skipped(sid)]
    assert reasons == ["the source no longer has these exact bytes"]


def test_a_local_source_keeps_no_blob_and_is_not_changed(index, tmp_path):
    (tmp_path / "f").mkdir()
    (tmp_path / "f" / "big.md").write_bytes(big_text("delta"))
    sid = index.add_source(FolderConnector(tmp_path / "f"))
    index.scan([sid])
    assert index.search("delta")
    vid = index.store.one("SELECT id FROM version WHERE source_id = ?", (sid,))[0]
    assert retention.after_convert(index, vid) is False


# ------------------------------------------------------------------ removal


@pytest.fixture
def two_sources(index, tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "one.md").write_text(
            f"# One {name}\n\nText of {name} about nanodiscs.\n"
        )
        (tmp_path / name / "two.md").write_text(f"# Two {name}\n\nSee one. Text {name}.\n")
    a = index.add_source(FolderConnector(tmp_path / "a"))
    b = index.add_source(FolderConnector(tmp_path / "b"))
    index.scan()
    return a, b


def test_remove_source_deletes_all(index, two_sources):
    a, b = two_sources
    before_b = rows_of(index, b)
    assert rows_of(index, a)["chunk"] > 0
    out = retention.remove_source(index, a)
    assert out == {"account_revoked": False, "kept_for_findings": 0, "removed_items": 2}
    assert set(rows_of(index, a).values()) == {0}
    assert rows_of(index, b) == before_b  # the other source is not touched
    assert a not in index.sources()
    removed = [e for e in ss.events_after(index.store, 0) if e["topic"] == "source.removed"]
    assert removed[-1]["data"] == {"id": a, "kept_for_findings": 0, "removed_items": 2}
    assert [
        e["data"]["status"] for e in ss.events_after(index.store, 0) if e["topic"] == "source.state"
    ][-1] == "removing"


def test_items_of_a_finding_keep_their_opening_only(index, two_sources):
    a, _ = two_sources
    opening = index.evidence_opening(a, "one.md")
    index.record_finding("ab" * 32, [(a, "one.md")])
    out = retention.remove_source(index, a)
    assert out["kept_for_findings"] == 1 and out["removed_items"] == 1
    left = rows_of(index, a)
    assert (left["item"], left["version"]) == (1, 1)
    assert left["document"] == left["chunk"] == left["fact"] == left["job"] == 0
    assert index.evidence_opening(a, "one.md").to_json() == opening.to_json()
    v = index.store.one("SELECT blob, extra FROM version WHERE source_id = ?", (a,))
    assert v["blob"] is None and v["extra"] is None
    item = index.store.one("SELECT path, present FROM item WHERE source_id = ?", (a,))
    assert item["path"] is None and item["present"] == 0
    # The source is gone for each list and each scan.
    assert a not in index.sources()
    assert index.streams.pending(a) == [] and index.streams.checkpoint(object(), a) is None
    assert index.search("nanodiscs") and all(h.source_id != a for h in index.search("nanodiscs"))
    assert index.store.one("SELECT label, config FROM source WHERE id = ?", (a,))["label"] == ""


def test_removal_can_run_again_after_a_stop(index, two_sources, monkeypatch):
    a, _ = two_sources
    real = retention._chunks
    calls = {"n": 0}

    def stops(ids, n=retention.BATCH):
        calls["n"] += 1
        if calls["n"] == 2:  # the process stops after the versions, before the items
            raise RuntimeError("stop")
        return real(ids, n)

    monkeypatch.setattr(retention, "_chunks", stops)
    with pytest.raises(RuntimeError):
        retention.remove_source(index, a)
    assert ss.read(index.store, a).stored_status == "removing"
    assert a not in index.sources() and index.scan([a]).new == []
    monkeypatch.setattr(retention, "_chunks", real)
    retention.remove_source(index, a)
    assert set(rows_of(index, a).values()) == {0}


class FakeCredentials:
    def __init__(self) -> None:
        self.revoked: list[str] = []

    def revoke(self, account_id: str) -> bool:
        self.revoked.append(account_id)
        return True


def test_the_account_is_revoked_with_its_last_source(index, two_sources):
    a, b = two_sources
    creds = index.credentials = FakeCredentials()
    for sid in (a, b):
        ss.set_account(index.store, sid, "acct1", now=index.clock())
    assert retention.remove_source(index, a)["account_revoked"] is False
    assert creds.revoked == []  # source b still uses the account
    assert retention.remove_source(index, b)["account_revoked"] is True
    assert creds.revoked == ["acct1"]


# -------------------------------------------------------------------- route


def test_delete_route(member, places):  # noqa: F811
    svc, tc = member
    sid = add(tc, kind="obsidian", path=str(places["vault"]))["sources"][0]
    with svc.session(index=True) as (_, idx):
        idx.record_finding("cd" * 32, [(sid, "Home.md")])
    r = tc.request("DELETE", f"/api/sources/{sid}", json={"delete_data": False}, headers=ORIGIN)
    assert r.status_code == 400 and r.json()["code"] == "keep_data"
    r = tc.request("DELETE", f"/api/sources/{sid}", json={"delete_data": True}, headers=ORIGIN)
    assert r.json() == {"account_revoked": False, "kept_for_findings": 1, "removed_items": 9}
    assert all(s["id"] != sid for s in tc.get("/api/sources").json()["sources"])
    assert tc.request("DELETE", f"/api/sources/{sid}", headers=ORIGIN).status_code == 409
    with svc.session(index=True) as (_, idx):
        left = rows_of(idx, sid)
    assert (left["item"], left["version"], left["chunk"], left["fact"]) == (1, 1, 0, 0)
    removed = events(svc, "source.removed")
    assert removed[-1]["data"] == {"id": sid, "kept_for_findings": 1, "removed_items": 9}
    assert str(places["vault"]) not in json.dumps(events(svc))
    # A source with no finding goes completely; a second delete finds nothing.
    other = add(tc, kind="folder", path=str(places["work"] / "notes"))["sources"][0]
    assert tc.request("DELETE", f"/api/sources/{other}", headers=ORIGIN).status_code == 200
    assert tc.request("DELETE", f"/api/sources/{other}", headers=ORIGIN).status_code == 404


def test_a_lab_source_is_not_removed_here(member, places, monkeypatch):  # noqa: F811
    svc, tc = member

    class LabFolder(FolderConnector):
        kind = "lab_folder_toy"
        own = False

    SOURCES.register(LabFolder.kind, LabFolder)
    try:
        with svc.session(index=True) as (_, idx):
            sid = idx.add_source(LabFolder(places["work"] / "notes"))
        for method, path in (
            ("DELETE", f"/api/sources/{sid}"),
            ("POST", f"/api/sources/{sid}/pause"),
            ("PATCH", f"/api/sources/{sid}"),
        ):
            r = tc.request(method, path, json={}, headers=ORIGIN)
            assert r.status_code == 403 and r.json()["code"] == "lab_source", path
        row = next(s for s in tc.get("/api/sources").json()["sources"] if s["id"] == sid)
        assert row["own"] is False
    finally:
        SOURCES.unregister(LabFolder.kind)
