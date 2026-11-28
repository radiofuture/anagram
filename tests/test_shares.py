"""Shares to people, sets (`includes` links), audience, and new
versions that follow the audience. People in two labs on one node."""

from __future__ import annotations

import pytest
from sharekit import commit, make_share_net, people

from anagram.core.errors import ClientError
from anagram.network.sharing.app.grants import ThirdPartyWarning
from anagram.proofs.records import LINK_INCLUDES, LINK_SUPERSEDES, Link


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "okafor", "varga")
    # Chen and Okafor are in two different labs.
    p["chen"].labs.lab_create("Chen lab")
    p["okafor"].labs.lab_create("Okafor lab")
    return net, p


def test_share_to_a_person_in_another_lab(world, tmp_path):
    net, p = world
    chen, okafor, varga = p["chen"], p["okafor"], p["varga"]
    root = commit(chen, tmp_path, {"plan.md": b"# Plan\nGrow cells."})
    target = chen.shares.resolve_target(okafor.device.subject)
    out = chen.shares.share(root, [target["target"]])
    assert out == {
        "findings": [root],
        "shared": [{"people": 1, "target": okafor.device.subject}],
        "waiting": [],
    }
    (g,) = okafor.grants.inbox()
    assert okafor.grants.open_grant(g["grant_id"], tmp_path / "out")["root"] == root
    assert varga.grants.inbox() == []
    fid = chen.vault.get(root).finding_id
    (sh,) = chen.share_store.shares_of(fid)
    assert (sh["target"], sh["state"]) == (okafor.device.subject, "active")
    assert [e["kind"] for e in chen.share_store.share_events(finding_id=fid)] == ["shared"]
    # Sharing again sends nothing new.
    again = chen.shares.share(root, [okafor.device.subject])
    assert again["shared"] == [{"people": 1, "target": okafor.device.subject}]
    assert len(okafor.grants.inbox()) == 1
    assert chen.shares.audience(fid) == {okafor.device.subject}


def test_share_a_set(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    a = commit(chen, tmp_path, {"a.md": b"A"}, claim="Part A")
    b = commit(chen, tmp_path, {"b.md": b"B"}, claim="Part B")
    c = commit(
        chen,
        tmp_path,
        {"c.md": b"C"},
        claim="Part C",
        links=[Link(LINK_INCLUDES, bytes.fromhex(a))],
    )
    parent = commit(
        chen,
        tmp_path,
        {"p.md": b"Parent"},
        claim="The set",
        links=[Link(LINK_INCLUDES, bytes.fromhex(b)), Link(LINK_INCLUDES, bytes.fromhex(c))],
    )
    assert chen.shares.set_roots(parent) == [parent, b, c, a]
    out = chen.shares.share(parent, [okafor.device.subject])
    assert out["findings"] == [parent, b, c, a]
    assert len(okafor.grants.inbox()) == 4
    fids = {chen.vault.get(r).finding_id: r for r in (parent, b, c, a)}
    sets = {s["finding_id"]: s["set_root"] for s in chen.share_store.shares_of()}
    assert sets[chen.vault.get(parent).finding_id] is None
    assert {sets[f] for f in fids if fids[f] != parent} == {parent}
    # Without the included findings: only the parent.
    varga = p["varga"]
    assert chen.shares.share(parent, [varga.device.subject], with_included=False)["findings"] == [
        parent
    ]
    assert len(varga.grants.inbox()) == 1


def test_third_party_gate_covers_the_whole_set(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    child = commit(chen, tmp_path, {"mail.eml": b"quoted"}, third_party=[True])
    parent = commit(
        chen, tmp_path, {"p.md": b"P"}, links=[Link(LINK_INCLUDES, bytes.fromhex(child))]
    )
    with pytest.raises(ThirdPartyWarning):
        chen.shares.share(parent, [okafor.device.subject])
    assert okafor.grants.inbox() == [] and chen.share_store.shares_of() == []
    chen.shares.share(parent, [okafor.device.subject], warnings_ack=True)
    assert len(okafor.grants.inbox()) == 2


def test_new_version_follows_the_audience(world, tmp_path):
    net, p = world
    chen, okafor, varga = p["chen"], p["okafor"], p["varga"]
    v1 = commit(chen, tmp_path, {"r.md": b"v1"})
    chen.shares.share(v1, [okafor.device.subject])
    v2 = commit(chen, tmp_path, {"r.md": b"v2"}, links=[Link(LINK_SUPERSEDES, bytes.fromhex(v1))])
    out = chen.shares.share_new_version(v2)
    assert out["shared"] == [{"people": 1, "target": okafor.device.subject}]
    assert len(okafor.grants.inbox()) == 2 and varga.grants.inbox() == []
    fid = chen.vault.get(v2).finding_id
    kinds = [e["kind"] for e in chen.share_store.share_events(finding_id=fid)]
    assert kinds == ["shared", "shared", "new_version"]
    # The setting off: a new version goes to nobody.
    chen.config.setdefault("sharing", {})["follow_versions"] = False
    v3 = commit(chen, tmp_path, {"r.md": b"v3"}, links=[Link(LINK_SUPERSEDES, bytes.fromhex(v2))])
    assert chen.shares.share_new_version(v3)["shared"] == []
    assert len(okafor.grants.inbox()) == 2


def test_audience_leaves_out_a_stopped_share(world, tmp_path):
    net, p = world
    chen, okafor, varga = p["chen"], p["okafor"], p["varga"]
    root = commit(chen, tmp_path, {"r.md": b"x"})
    chen.shares.share(root, [okafor.device.subject, varga.device.subject])
    fid = chen.vault.get(root).finding_id
    assert chen.shares.audience(fid) == {okafor.device.subject, varga.device.subject}
    chen.vault.db.execute(
        "UPDATE shares SET state = 'stopped' WHERE target = ?", (varga.device.subject,)
    )
    assert chen.shares.audience(fid) == {okafor.device.subject}


def test_share_targets(world, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"r.md": b"x"})
    with pytest.raises(ClientError, match="lab"):
        chen.shares.share(root, ["lab:lab-" + "00" * 8])
    with pytest.raises(ClientError, match="person ID"):
        chen.shares.share(root, ["fake-okafor"])
    # ORCID iD: findable gives the pid; not findable is a person to invite.
    assert chen.shares.resolve_target("fake-okafor")["kind"] == "unknown_orcid"
    okafor.account.set_findable(True)
    assert chen.shares.resolve_target("fake-okafor")["target"] == okafor.device.subject
    assert chen.shares.resolve_target("lab-" + "ab" * 8)["kind"] == "lab"
    with pytest.raises(ClientError):
        chen.shares.resolve_target("nonsense")
    # Sharing with oneself sends nothing.
    assert chen.shares.share(root, [chen.device.subject])["shared"] == []
