"""Share a finding with my own lab. The finding goes into the lab
space (`lab_publish`), not into a grant for each member. A member of the
lab reads it there; a member of another lab gets nothing; a lab of another
person is refused before any send."""

from __future__ import annotations

import pytest
from sharekit import commit, make_share_net, people

from anagram.core.errors import ClientError
from anagram.core.nodeapi import NodeHTTPError
from anagram.proofs.records import LINK_INCLUDES, LINK_SUPERSEDES, Link

CLAIM = "Gel shows two bands at 40 kDa.\nThe second band is the dimer."


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    p = people(net, tmp_path, "chen", "lee", "okafor")
    lab = p["chen"].labs.lab_create("Chen lab")["lab_id"]
    p["chen"].labs.lab_add(lab, p["lee"].device.subject)
    other = p["okafor"].labs.lab_create("Okafor lab")["lab_id"]
    return net, p, lab, other


def test_my_lab_reads_the_finding_in_the_lab_space(world, tmp_path):
    _, p, lab, _ = world
    chen, lee, okafor = p["chen"], p["lee"], p["okafor"]
    root = commit(chen, tmp_path, {"gel.md": b"# Gel\nTwo bands."}, claim=CLAIM)
    out = chen.shares.share(root, ["lab:" + lab])
    assert out == {"findings": [root], "shared": [{"people": 1, "target": "lab:" + lab}],
                   "waiting": []}  # fmt: skip
    # No grant: the lab space carries it.
    assert chen.vault.grants_sent(root) == [] and lee.grants.inbox() == []
    lee.labs.lab_sync(lab)
    (item,) = lee.lab_space.lab_items(lab)
    assert item["kind"] == "finding" and item["type"] == "finding"
    assert item["title"] == "Gel shows two bands at 40 kDa."
    assert item["author"] == chen.device.subject and item["finding"]["root"] == root
    assert item["attachments"] == []
    assert lee.lab_space.lab_item(lab, item["item_id"])["text"] == CLAIM
    # A member of another lab gets nothing.
    assert okafor.labs.lab_sync(lab)["labs"][lab] == {"removed": True}
    with pytest.raises(NodeHTTPError) as err:
        okafor.device.http.call("GET", f"/labs/{lab}/space/records?after=0&limit=200", auth=True)
    assert err.value.status == 404
    assert okafor.lab_space.lab_items(lab) == [] and okafor.grants.inbox() == []
    # The share row and the history show the lab.
    fid = chen.vault.get(root).finding_id
    (sh,) = chen.share_store.shares_of(fid)
    assert (sh["target"], sh["state"]) == ("lab:" + lab, "active")
    (ev,) = chen.share_store.share_events(finding_id=fid)
    assert (ev["kind"], ev["person"], ev["target"]) == ("shared", None, "lab:" + lab)
    assert chen.shares.audience(fid) == set()  # a lab is not a person of the audience
    # Sharing again writes no new revision.
    chen.shares.share(root, ["lab:" + lab])
    lee.labs.lab_sync(lab)
    assert [i["rev"] for i in lee.lab_space.lab_items(lab)] == [1]


def test_a_lab_of_another_person_is_refused(world, tmp_path):
    _, p, _, other = world
    chen, okafor = p["chen"], p["okafor"]
    root = commit(chen, tmp_path, {"r.md": b"x"}, claim="A result")
    with pytest.raises(ClientError, match="lab that you are in"):
        chen.shares.share(root, [okafor.device.subject, "lab:" + other])
    # Nothing was sent, also not to the person in the same call.
    okafor.labs.lab_sync(other)
    assert okafor.lab_space.lab_items(other) == [] and okafor.grants.inbox() == []
    assert chen.share_store.shares_of() == []
    with pytest.raises(ClientError):
        chen.shares.share(root, ["lab:not-a-lab"])


def test_a_new_version_is_a_new_revision_of_the_lab_item(world, tmp_path):
    _, p, lab, _ = world
    chen, lee = p["chen"], p["lee"]
    v1 = commit(chen, tmp_path, {"r.md": b"v1"}, claim="First claim")
    chen.shares.share(v1, ["lab:" + lab])
    v2 = commit(chen, tmp_path, {"r.md": b"v2"}, claim="Second claim",
                links=[Link(LINK_SUPERSEDES, bytes.fromhex(v1))])  # fmt: skip
    out = chen.shares.share_new_version(v2)
    assert out["shared"] == [{"people": 1, "target": "lab:" + lab}]
    lee.labs.lab_sync(lab)
    (item,) = lee.lab_space.lab_items(lab)
    assert item["rev"] == 2 and item["finding"]["root"] == v2
    assert item["title"] == "Second claim"


def test_a_set_puts_each_finding_into_the_lab_space(world, tmp_path):
    _, p, lab, _ = world
    chen, lee = p["chen"], p["lee"]
    a = commit(chen, tmp_path, {"a.md": b"A"}, claim="Part A")
    parent = commit(chen, tmp_path, {"p.md": b"P"}, claim="The set",
                    links=[Link(LINK_INCLUDES, bytes.fromhex(a))])  # fmt: skip
    chen.shares.share(parent, ["lab:" + lab])
    lee.labs.lab_sync(lab)
    assert sorted(i["title"] for i in lee.lab_space.lab_items(lab)) == ["Part A", "The set"]
    sets = {s["finding_id"]: s["set_root"] for s in chen.share_store.shares_of()}
    assert sets[chen.vault.get(a).finding_id] == parent


def test_stop_sharing_with_my_lab_removes_the_item(world, tmp_path):
    _, p, lab, _ = world
    chen, lee = p["chen"], p["lee"]
    root = commit(chen, tmp_path, {"r.md": b"x"}, claim="A result")
    chen.shares.share(root, ["lab:" + lab])
    lee.labs.lab_sync(lab)
    assert len(lee.lab_space.lab_items(lab)) == 1
    out = chen.shares.stop_sharing(root, "lab:" + lab)
    assert out["target"] == "lab:" + lab
    lee.labs.lab_sync(lab)
    assert lee.lab_space.lab_items(lab) == []
    fid = chen.vault.get(root).finding_id
    assert [s["state"] for s in chen.share_store.shares_of(fid)] == ["stopped"]
    assert [e["kind"] for e in chen.share_store.share_events(finding_id=fid)] == [
        "shared",
        "stopped",
    ]
    # A new version does not go to a stopped lab.
    v2 = commit(chen, tmp_path, {"r.md": b"y"}, claim="Later",
                links=[Link(LINK_SUPERSEDES, bytes.fromhex(root))])  # fmt: skip
    assert chen.shares.share_new_version(v2)["shared"] == []
    # A second stop is refused; a new share makes a new item.
    with pytest.raises(ClientError, match="not shared"):
        chen.shares.stop_sharing(root, "lab:" + lab)
    chen.shares.share(v2, ["lab:" + lab])
    lee.labs.lab_sync(lab)
    (item,) = lee.lab_space.lab_items(lab)
    assert item["title"] == "Later" and item["rev"] == 1
