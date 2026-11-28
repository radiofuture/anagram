"""The node read ledger, the receipt gate, fetch events, grant and
blob delete, and the grant list with no ciphertext."""

from __future__ import annotations

import secrets
from datetime import timedelta

import pytest
from sharekit import commit, make_share_net, people

from anagram.core.canonical import canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.signing import SigningKey
from anagram.core.nodeapi import NodeHTTPError
from anagram.network.formats.sharing import (
    make_read_receipt,
    read_receipt_id,
    read_receipt_log_entry,
    verify_fetch_event,
)
from anagram.proofs.log.checkpoint import open_checkpoint


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor", "varga")
    root = commit(p["chen"], tmp_path, {"plan.md": b"# Plan\nGrow cells.", "data.csv": b"a,b\n1,2"})
    gid = p["chen"].grants.grant(root, recipients=[p["okafor"].device.subject])["granted"][0][
        "grant_id"
    ]
    return net, p, root, gid


def receipt(client, gid, *, key=None, reader=None, at=None):
    return make_read_receipt(
        grant_id=bytes.fromhex(gid),
        reader=reader or client.device.subject,
        read_at=at or client.device.now(),
        salt=secrets.token_bytes(32),
        key=key or client.device.device_key(),
    )


def post(client, gid, doc):
    return client.device.http.call("POST", f"/grants/{gid}/receipts", {"receipt": doc}, auth=True)


def status_of(fn) -> int:
    with pytest.raises(NodeHTTPError) as exc:
        fn()
    return exc.value.status


def blobs_of(client, gid):
    return client.device.http.call("GET", f"/grants/{gid}", auth=True)["grant"]["blobs"]


def test_fetch_needs_read_receipt(world):
    net, p, root, gid = world
    okafor = p["okafor"]
    blob = p["chen"].vault.evidence_meta(root)[0]["blob_id"]
    assert status_of(lambda: okafor.device.http.call("GET", f"/grants/{gid}", auth=True)) == 428
    assert status_of(lambda: okafor.device.http.call("GET", f"/blobs/{blob}", auth=True)) == 428
    # The list opens nothing: each wrap has an empty ciphertext.
    listed = okafor.device.http.call("GET", "/grants", auth=True)["grants"]
    assert [g["grant"]["grant_id"] for g in listed] == [gid]
    assert all(w["ciphertext"] == "" for w in listed[0]["grant"]["wraps"])
    assert okafor.grants.inbox()[0]["for_this_device"]
    # After a receipt the grant and the blob come.
    post(okafor, gid, receipt(okafor, gid))
    assert blob in blobs_of(okafor, gid)
    assert okafor.device.http.call("GET", f"/blobs/{blob}", auth=True)


def test_sender_and_public_have_no_gate(world):
    net, p, root, gid = world
    chen = p["chen"]
    blob = chen.vault.evidence_meta(root)[0]["blob_id"]
    assert chen.device.http.call("GET", f"/grants/{gid}", auth=True)["grant"]["wraps"][0][
        "ciphertext"
    ]
    assert chen.device.http.call("GET", f"/blobs/{blob}", auth=True)
    chen.grants.publish(root)
    assert net.transport("GET", f"/blobs/{blob}", None)  # public, no session
    assert p["okafor"].device.http.call(
        "GET", f"/blobs/{blob}", auth=True
    )  # public wins over the gate


def test_receipt_answer_is_logged_and_signed(world):
    net, p, root, gid = world
    okafor = p["okafor"]
    doc = receipt(okafor, gid)
    out = post(okafor, gid, doc)
    assert out["receipt_id"] == read_receipt_id(doc)
    log = out["log"]
    assert log["entry"] == read_receipt_log_entry(doc)
    trust = okafor.device.trust()
    cp = open_checkpoint(log["checkpoint"], trust.log_keys, trust.witness_keys).checkpoint
    path = [bytes.fromhex(h) for h in log["inclusion"]]
    assert merkle.verify_inclusion(
        merkle.leaf_hash(canonical_json(log["entry"])), log["leaf_index"], cp.size, path, cp.root
    )
    ev = verify_fetch_event(
        out["event"], net.identity.key.public_bytes(), net.identity.cfg.node_key
    )
    assert (ev["seq"], ev["blob_id"], ev["receipt_id"]) == (1, None, out["receipt_id"])
    assert ev["reader"] == okafor.device.subject and ev["grant_id"] == gid
    # The same receipt again: the same answer, no second log entry.
    before = net.service.checkpoint()
    again = post(okafor, gid, doc)
    assert again["receipt_id"] == out["receipt_id"] and again["event"] == out["event"]
    assert net.service.checkpoint() == before


def test_each_blob_answer_adds_a_signed_event(world):
    net, p, root, gid = world
    okafor = p["okafor"]
    rid = post(okafor, gid, receipt(okafor, gid))["receipt_id"]
    blobs = blobs_of(okafor, gid)
    for b in blobs:
        okafor.device.http.call("GET", f"/blobs/{b}", auth=True)
    got = p["chen"].device.http.call("GET", "/grants/sent/reads?since=0", auth=True)
    events = got["events"]
    assert [e["seq"] for e in events] == list(range(1, len(blobs) + 2))
    assert [e["blob_id"] for e in events] == [None, *blobs]
    assert {e["receipt_id"] for e in events} == {rid}
    for e in events:
        verify_fetch_event(e, net.identity.key.public_bytes(), net.identity.cfg.node_key)
    assert [r["receipt"]["grant_id"] for r in got["receipts"]] == [gid]
    # The cursor gives only what is new.
    later = p["chen"].device.http.call(
        "GET", f"/grants/sent/reads?since={got['cursor']}", auth=True
    )
    assert later["events"] == [] and later["receipts"] == []


def test_receipt_refusals(world):
    net, p, root, gid = world
    okafor, varga = p["okafor"], p["varga"]
    # Not the recipient of the grant.
    assert status_of(lambda: post(varga, gid, receipt(varga, gid))) == 404
    # A key that is not an active device key of the reader.
    stranger = SigningKey.generate()
    assert status_of(lambda: post(okafor, gid, receipt(okafor, gid, key=stranger))) == 403
    # A receipt for another reader.
    other = receipt(varga, gid)
    assert status_of(lambda: post(okafor, gid, other)) == 403
    # A receipt for another grant ID in the path.
    assert status_of(lambda: post(okafor, gid, receipt(okafor, "00" * 16))) == 403
    # A time in the future.
    future = okafor.device.now() + timedelta(hours=1)
    assert status_of(lambda: post(okafor, gid, receipt(okafor, gid, at=future))) == 400
    # A changed receipt does not verify.
    doc = receipt(okafor, gid)
    doc["read_at"] = "2026-10-15T11:00:00Z"
    assert status_of(lambda: post(okafor, gid, doc)) == 400
    # Unknown grant.
    assert status_of(lambda: post(okafor, "11" * 16, receipt(okafor, "11" * 16))) == 404


def test_receipt_window(world):
    net, p, root, gid = world
    okafor = p["okafor"]
    post(okafor, gid, receipt(okafor, gid))
    assert blobs_of(okafor, gid)
    net.clock.t += 25 * 3600
    assert status_of(lambda: blobs_of(okafor, gid)) == 428
    post(okafor, gid, receipt(okafor, gid))
    assert blobs_of(okafor, gid)


def test_reads_go_only_to_the_sender(world):
    net, p, root, gid = world
    okafor = p["okafor"]
    post(okafor, gid, receipt(okafor, gid))
    assert okafor.device.http.call("GET", "/grants/sent/reads", auth=True)["events"] == []
    assert p["varga"].device.http.call("GET", "/grants/sent/reads", auth=True)["receipts"] == []
    assert len(p["chen"].device.http.call("GET", "/grants/sent/reads", auth=True)["receipts"]) == 1


def test_delete_grant(world):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    post(okafor, gid, receipt(okafor, gid))
    assert (
        status_of(lambda: okafor.device.http.call("DELETE", f"/grants/{gid}", None, auth=True))
        == 404
    )
    assert chen.device.http.call("DELETE", f"/grants/{gid}", None, auth=True)["deleted"]
    assert status_of(lambda: okafor.device.http.call("GET", f"/grants/{gid}", auth=True)) == 404
    blob = chen.vault.evidence_meta(root)[0]["blob_id"]
    assert status_of(lambda: okafor.device.http.call("GET", f"/blobs/{blob}", auth=True)) == 404
    assert okafor.grants.inbox() == []
    # The read history stays for the owner.
    assert len(chen.device.http.call("GET", "/grants/sent/reads", auth=True)["receipts"]) == 1


def test_delete_blob(world, tmp_path):
    net, p, root, gid = world
    chen, okafor = p["chen"], p["okafor"]
    b0 = chen.vault.evidence_meta(root)[0]["blob_id"]
    assert (
        status_of(lambda: okafor.device.http.call("DELETE", f"/blobs/{b0}", None, auth=True)) == 404
    )
    assert chen.device.http.call("DELETE", f"/blobs/{b0}", None, auth=True)["deleted"]
    assert status_of(lambda: chen.device.http.call("GET", f"/blobs/{b0}", auth=True)) == 404
    assert not (net.vault.blob_dir / b0).exists()
    # A blob that a public release lists stays.
    other = commit(chen, tmp_path, {"note.txt": b"public note"})
    chen.grants.publish(other)
    b1 = chen.vault.evidence_meta(other)[0]["blob_id"]
    assert (
        status_of(lambda: chen.device.http.call("DELETE", f"/blobs/{b1}", None, auth=True)) == 409
    )


def test_node_home_builds_the_ledger(tmp_path):
    from fastapi.testclient import TestClient

    from anagram.shell.node.home import NodeHome

    nh = NodeHome(tmp_path / "node")
    nh.create(origin="node.test/log", public_url="https://node.test", community="C")
    tc = TestClient(nh.app(), base_url="https://node.test")
    # The routes exist (no session: 401, not 404).
    assert tc.post("/grants/" + "00" * 16 + "/receipts", json={"receipt": {}}).status_code == 401
    assert tc.get("/grants/sent/reads").status_code == 401
    assert tc.delete("/grants/" + "00" * 16).status_code == 401
    assert (tmp_path / "node" / "reads.sqlite").exists()
