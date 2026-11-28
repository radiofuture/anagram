"""Read receipts: the reader's client posts read receipts (also from an offline
queue); the owner's client fetches and checks them (forged read, event gap)."""

from __future__ import annotations

import json
import secrets

import pytest
from conftest import make_net
from sharekit import commit, make_share_net, people

from anagram.core.crypto.signing import SigningKey
from anagram.network.formats.sharing import make_read_receipt, read_receipt_log_entry
from anagram.network.sharing.app.tables import POSTED_PREFIX, QUEUE_PREFIX


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor")
    root = commit(p["chen"], tmp_path, {"plan.md": b"# Plan\nGrow cells.", "data.csv": b"a,b\n1,2"})
    gid = p["chen"].grants.grant(root, recipients=[p["okafor"].device.subject])["granted"][0][
        "grant_id"
    ]
    return net, p, root, gid


def test_open_posts_a_receipt_and_owner_sees_the_read(world, tmp_path):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    out = okafor.grants.open_grant(gid, tmp_path / "out")
    assert out["verified"]
    changes = chen.read_records.sync_reads()
    reads = [c for c in changes if c["kind"] == "read"]
    assert len(reads) == 1
    assert reads[0]["reader"] == okafor.device.subject and reads[0]["root"] == root
    assert reads[0]["reads"] == 1
    assert not [c for c in changes if c["kind"] == "anomaly"]
    rows = chen.share_store.reads_of(grant_id=gid)
    assert len(rows) == 1 and rows[0]["verified"]
    assert rows[0]["reader_key"] == okafor.device.my_device()["ed25519"]
    # One event for the receipt and one for each blob, all verified and stored.
    events = chen.share_store.fetch_events_of(gid)
    assert [e["seq"] for e in events] == [1, 2, 3]
    finding_id = chen.vault.get(root).finding_id
    kinds = [e["kind"] for e in chen.share_store.share_events(finding_id=finding_id)]
    assert kinds == ["read"]
    # A second sync gives nothing new.
    assert chen.read_records.sync_reads() == []


def test_one_receipt_in_each_window(world, tmp_path):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    okafor.grants.open_grant(gid, tmp_path / "a")
    okafor.grants.open_grant(gid, tmp_path / "b")
    chen.read_records.sync_reads()
    assert len(chen.share_store.reads_of(grant_id=gid)) == 1
    net.clock.t += 24 * 3600
    okafor.grants.open_grant(gid, tmp_path / "c")
    changes = chen.read_records.sync_reads()
    assert [c["reads"] for c in changes if c["kind"] == "read"] == [2]


def test_gated_call_gets_a_new_receipt_after_the_node_window(world):
    net, p, root, gid = world
    okafor = p["okafor"]
    okafor.reads.gate(gid)
    net.clock.t += 25 * 3600
    # The client thinks its receipt is new; the node does not.
    okafor.vault.kv_set(
        POSTED_PREFIX + gid, json.dumps({"posted_at": okafor.clock(), "receipt_id": "00" * 16})
    )
    doc = okafor.reads.gated_call(gid, "GET", f"/grants/{gid}")
    assert doc["grant"]["grant_id"] == gid


def test_offline_read_is_queued_and_posted_later(world):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    rid = okafor.reads.queue(gid)
    assert [k for k, _ in okafor.vault.kv_items(QUEUE_PREFIX)] == [QUEUE_PREFIX + rid]
    read_at = json.loads(okafor.vault.kv_get(QUEUE_PREFIX + rid))["receipt"]["read_at"]
    net.clock.t += 3 * 3600
    assert okafor.reads.flush_queue() == [rid]
    assert okafor.vault.kv_items(QUEUE_PREFIX) == []
    changes = chen.read_records.sync_reads()
    assert [(c["kind"], c["read_at"]) for c in changes] == [("read", read_at)]


def test_queued_receipt_for_a_withdrawn_grant_is_dropped(world):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    okafor.reads.queue(gid)
    chen.device.http.call("DELETE", f"/grants/{gid}", None, auth=True)
    assert okafor.reads.flush_queue() == []
    assert okafor.vault.kv_items(QUEUE_PREFIX) == []


def _forge(net, okafor, gid, key):
    """The node stores a receipt that it made itself and logs its commitment."""
    receipt = make_read_receipt(
        grant_id=bytes.fromhex(gid),
        reader=okafor.device.subject,
        read_at=okafor.device.now(),
        salt=secrets.token_bytes(32),
        key=key,
    )
    entry = read_receipt_log_entry(receipt)
    res = net.service.submit(entry)
    log = {k: res[k] for k in ("checkpoint", "inclusion", "leaf_index", "tree_size")}
    log["entry"] = entry
    grant = net.vault.grant_meta(gid)
    event_id, _ = net.reads._add_event(grant, okafor.device.subject, None, "ab" * 16)
    net.reads._db.execute(
        "INSERT INTO read_receipts (receipt_id, grant_id, sender, reader, doc, log,"
        " received_at, event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "ab" * 16,
            gid,
            grant["sender"],
            okafor.device.subject,
            json.dumps(receipt),
            json.dumps(log),
            net.identity.now(),
            event_id,
        ),
    )


def test_node_cannot_forge_read(world):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    _forge(net, okafor, gid, SigningKey.generate())
    changes = chen.read_records.sync_reads()
    assert [(c["kind"], c["detail"]) for c in changes] == [("anomaly", "unknown_reader_key")]
    assert chen.share_store.reads_of(grant_id=gid) == []
    finding_id = chen.vault.get(root).finding_id
    assert [e["kind"] for e in chen.share_store.share_events(finding_id=finding_id)] == ["anomaly"]


def test_receipt_not_in_log_is_refused(world):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    okafor.reads.gate(gid)
    (doc,) = net.reads._db.execute("SELECT log FROM read_receipts").fetchone()
    log = json.loads(doc)
    log["leaf_index"] = 0
    net.reads._db.execute("UPDATE read_receipts SET log = ?", (json.dumps(log),))
    changes = chen.read_records.sync_reads()
    assert [(c["kind"], c["detail"]) for c in changes] == [("anomaly", "not_in_log")]


def test_fetch_event_gap_is_reported(world, tmp_path):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    okafor.grants.open_grant(gid, tmp_path / "out")
    net.reads._db.execute("DELETE FROM fetch_events WHERE seq = 2")
    changes = chen.read_records.sync_reads()
    gaps = [c for c in changes if c["kind"] == "anomaly"]
    assert [(c["detail"], c["missing"]) for c in gaps] == [("event_gap", [2])]
    assert [c["kind"] for c in changes if c["kind"] == "read"] == ["read"]


def test_changed_event_is_reported(world, tmp_path):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    okafor.grants.open_grant(gid, tmp_path / "out")
    (doc,) = net.reads._db.execute("SELECT doc FROM fetch_events WHERE seq = 3").fetchone()
    ev = json.loads(doc)
    ev["at"] = "2026-10-15T00:00:00Z"
    net.reads._db.execute("UPDATE fetch_events SET doc = ? WHERE seq = 3", (json.dumps(ev),))
    changes = chen.read_records.sync_reads()
    assert ("anomaly", "bad_event") in [(c["kind"], c.get("detail")) for c in changes]
    assert [e["seq"] for e in chen.share_store.fetch_events_of(gid)] == [1, 2]


def test_node_with_no_read_ledger(tmp_path):
    net = make_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor")
    root = commit(p["chen"], tmp_path, {"plan.md": b"# Plan"})
    gid = p["chen"].grants.grant(root, recipients=[p["okafor"].device.subject])["granted"][0][
        "grant_id"
    ]
    assert p["okafor"].reads.gate(gid) is None
    assert p["okafor"].grants.open_grant(gid, tmp_path / "out")["verified"]
    assert p["chen"].read_records.sync_reads() == []


def test_m15_fetch_payload_checks_grant_id_and_uses_gated_call(world, monkeypatch):
    from anagram.core.errors import ClientError

    net, p, root, gid = world
    okafor = p["okafor"]
    # Expire the node's receipt window while client cache still thinks it's fresh -> 428 retry.
    okafor.reads.gate(gid)
    net.clock.t += 25 * 3600
    payload, env = okafor.grants.fetch_payload(gid)
    assert env["grant_id"] == gid and payload["receipt"]["grant_id"] == gid

    # Mismatched grant_id returned by a misbehaving node is rejected.
    orig = okafor.grants.hooks.gated_call

    def swapped(grant_id, method, path):
        res = orig(grant_id, method, path)
        res["grant"]["grant_id"] = "00" * 16
        return res

    monkeypatch.setattr(okafor.grants.hooks, "gated_call", swapped)
    with pytest.raises(ClientError, match="grant ID"):
        okafor.grants.fetch_payload(gid)
