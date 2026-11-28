"""The encrypted received store. The reader keeps only ciphertext
on disk; the payload is sealed in the vault; old plaintext folders move in.
No network."""

from __future__ import annotations

import pytest
from readkit import ALL, csv_bytes, pdf_bytes
from sharekit import commit, make_share_net, people

from anagram.core.errors import ClientError
from anagram.network.sharing.app.tables import READING_PREFIX

SECRET = b"# Plan\nThe secret growth medium is XK-77.\n"


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor")
    return net, p


def _all_bytes(folder):
    return b"".join(f.read_bytes() for f in folder.rglob("*") if f.is_file())


def test_open_received_keeps_no_plaintext(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"plan.md": SECRET, "data.csv": csv_bytes()})
    chen.shares.share(root, [okafor.device.subject])
    (g,) = okafor.grants.inbox()
    gid = g["grant_id"]
    model = okafor.received.open_received(gid)
    assert model["verified"] and model["root"] == root and model["claim"] == "A result"
    assert model["owner"]["subject"] == chen.device.subject
    assert [it["view"] for it in model["items"]] == ["text", "table"]
    assert any("XK-77" in b["text"] for b in model["items"][0]["blocks"])
    folder = okafor.home / "received" / gid
    assert sorted(f.name for f in folder.iterdir()) == ["0.blob", "1.blob", "reading.blob"]
    assert b"XK-77" not in _all_bytes(okafor.home)
    # The files come back from the store, in memory.
    assert b"".join(okafor.received.received_file(gid, 0)) == SECRET
    assert okafor.received.received_reading(gid)["items"][1]["table"]["total_rows"] == 3
    saved = okafor.received.save_received(gid, tmp_path / "saved")
    assert [p.split("/")[-1] for p in saved] == ["0-plan.md", "1-data.csv"]
    with pytest.raises(ClientError):
        list(okafor.received.received_file(gid, 9))
    # The reader fetched the reading copy from the owner (one more fetch event).
    chen.read_records.sync_reads()
    assert [e["seq"] for e in chen.share_store.fetch_events_of(gid)] == [1, 2, 3, 4]


def test_figures_are_not_in_the_reading_model(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"analysis.ipynb": ALL["analysis.ipynb"]()})
    chen.shares.share(root, [okafor.device.subject])
    gid = okafor.grants.inbox()[0]["grant_id"]
    (item,) = okafor.received.open_received(gid)["items"]
    assert item["figures"] == [{"id": "code-1-0", "media_type": "image/png"}]
    (full,) = okafor.received.received_reading(gid)["items"]
    assert full["figures"][0]["data"]


def test_old_grant_gets_a_local_reading_copy(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"paper.pdf": pdf_bytes()})
    # A plain grant (the CLI path) has no reading copy.
    gid = chen.grants.grant(root, recipients=[okafor.device.subject])["granted"][0]["grant_id"]
    assert chen.vault.kv_get(READING_PREFIX + root) is None
    (item,) = okafor.received.open_received(gid)["items"]
    assert item["view"] == "pdf" and "Cells grow" in item["blocks"][0]["text"]
    assert (okafor.home / "received" / gid / "reading.blob").is_file()


def test_unknown_or_unopened_grant(world, tmp_path):
    net, p = world
    okafor = p["okafor"]
    with pytest.raises(ClientError):
        okafor.received.open_received("../etc")
    with pytest.raises(ClientError, match="not opened"):
        list(okafor.received.received_file("ab" * 16, 0))


def test_old_plaintext_folders_move_in(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"plan.md": SECRET})
    gid = chen.grants.grant(root, recipients=[okafor.device.subject])["granted"][0]["grant_id"]
    old = okafor.home / "received" / gid
    okafor.grants.open_grant(gid, old)  # the old plaintext path
    assert b"XK-77" in _all_bytes(old)
    # A folder for a grant that is gone stays.
    gone = chen.grants.grant(root, recipients=[okafor.device.subject])["granted"][0]["grant_id"]
    okafor.grants.open_grant(gone, okafor.home / "received" / gone)
    chen.device.http.call("DELETE", f"/grants/{gone}", None, auth=True)
    out = okafor.received.migrate_received()
    assert out == {"kept": [gone], "moved": [gid]}
    assert sorted(f.name for f in old.iterdir()) == ["0.blob", "reading.blob"]
    assert b"".join(okafor.received.received_file(gid, 0)) == SECRET
    # A second run has nothing to do.
    assert okafor.received.migrate_received() == {"kept": [gone], "moved": []}
