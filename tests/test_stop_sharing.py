"""Stop sharing and "make a new version now". A stopped person
gets 404 and no later version. No network."""

from __future__ import annotations

import pytest
from sharekit import commit, make_share_net, people

from anagram.core.errors import ClientError
from anagram.core.nodeapi import NodeHTTPError
from anagram.network.sharing.app.tables import READING_PREFIX
from anagram.proofs.records import LINK_SUPERSEDES, Link


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor", "varga")
    return net, p


def test_stopped_person_gets_404_and_no_later_version(world, tmp_path):
    net, p = world
    chen, okafor, varga = p["chen"], p["okafor"], p["varga"]
    v1 = commit(chen, tmp_path, {"r.md": b"v1"})
    chen.shares.share(v1, [okafor.device.subject, varga.device.subject])
    gid = okafor.grants.inbox()[0]["grant_id"]
    okafor.received.open_received(gid)  # opened before the stop: it stays with them
    out = chen.shares.stop_sharing(v1, okafor.device.subject)
    assert out["withdrawn"] == [gid]
    with pytest.raises(NodeHTTPError) as exc:
        okafor.grants.open_grant(gid, tmp_path / "late")
    assert exc.value.status == 404
    assert okafor.grants.inbox() == []
    assert b"".join(okafor.received.received_file(gid, 0)) == b"v1"
    fid = chen.vault.get(v1).finding_id
    assert chen.shares.audience(fid) == {varga.device.subject}
    # A re-wrap does not post the grant again.
    assert chen.grants.sync_grants() == []
    assert okafor.grants.inbox() == []
    # The next version goes to Varga only.
    v2 = commit(chen, tmp_path, {"r.md": b"v2"}, links=[Link(LINK_SUPERSEDES, bytes.fromhex(v1))])
    assert chen.shares.share_new_version(v2)["shared"] == [
        {"people": 1, "target": varga.device.subject}
    ]
    assert okafor.grants.inbox() == [] and len(varga.grants.inbox()) == 2
    kinds = [e["kind"] for e in chen.share_store.share_events(person=okafor.device.subject)]
    assert kinds == ["shared", "stopped"]
    (sh,) = [s for s in chen.share_store.shares_of(fid) if s["target"] == okafor.device.subject]
    assert sh["state"] == "stopped" and sh["stopped_at"]


def test_share_again_after_a_stop(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"r.md": b"x"})
    chen.shares.share(root, [okafor.device.subject])
    chen.shares.stop_sharing(root, okafor.device.subject)
    assert okafor.grants.inbox() == []
    chen.shares.share(root, [okafor.device.subject])
    assert len(okafor.grants.inbox()) == 1
    assert chen.shares.audience(chen.vault.get(root).finding_id) == {okafor.device.subject}


def test_stop_a_ring_grant_is_an_explicit_exclusion(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"r.md": b"x"})
    chen.grants.grant(root, recipients=[okafor.device.subject])  # no share row (old path)
    fid = chen.vault.get(root).finding_id
    assert chen.shares.audience(fid) == {okafor.device.subject}
    chen.shares.stop_sharing(root, okafor.device.subject)
    assert chen.shares.audience(fid) == set() and okafor.grants.inbox() == []
    with pytest.raises(ClientError):
        chen.shares.stop_sharing(root, "lab:lab-" + "00" * 8)


def test_rekey_now(world, tmp_path):
    net, p = world
    chen, okafor, varga = p["chen"], p["okafor"], p["varga"]
    v1 = commit(chen, tmp_path, {"r.md": b"secret v1", "d.csv": b"a,b\n1,2\n"})
    chen.shares.share(v1, [okafor.device.subject, varga.device.subject])
    chen.shares.stop_sharing(v1, varga.device.subject)
    old_blobs = [m["blob_id"] for m in chen.vault.evidence_meta(v1).values()]
    old_blobs.append(chen.vault.kv_get(READING_PREFIX + v1))
    old_gid = okafor.grants.inbox()[0]["grant_id"]
    out = chen.shares.rekey_now(v1)
    v2 = out["root"]
    assert v2 != v1 and out["shared"] == [{"people": 1, "target": okafor.device.subject}]
    assert out["withdrawn"] == [old_gid]
    assert sorted(out["deleted_blobs"]) == sorted(old_blobs) and out["kept_blobs"] == []
    for b in old_blobs:
        assert net.vault.blob_owner(b) is None
    # Okafor has the new version only; Varga has nothing.
    (g,) = okafor.grants.inbox()
    assert g["grant_id"] != old_gid
    assert okafor.received.open_received(g["grant_id"])["root"] == v2
    assert varga.grants.inbox() == []
    assert chen.grants.content_key(v2) != chen.grants.content_key(v1)
    # The local records of the old blobs are gone, so an upload makes new ones.
    assert all(m["blob_id"] is None for m in chen.vault.evidence_meta(v1).values())


def test_rekey_keeps_a_public_blob(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    v1 = commit(chen, tmp_path, {"r.md": b"public"})
    chen.grants.publish(v1)
    chen.shares.share(v1, [okafor.device.subject])
    public = [m["blob_id"] for m in chen.vault.evidence_meta(v1).values()]
    out = chen.shares.rekey_now(v1)
    assert out["kept_blobs"] == public
    assert net.vault.blob_owner(public[0]) == chen.device.subject
