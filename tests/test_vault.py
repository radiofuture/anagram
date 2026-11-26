"""P3b: encrypted blobs, rings, grants, receipts, revocation, public release.

End to end over FastAPI TestClient with the synthetic community. No network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import make_net
from cryptography.exceptions import InvalidTag

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke, merkle
from anagram.core.errors import ClientError, LogMisbehaved
from anagram.core.nodeapi import NodeHTTPError
from anagram.network.formats.vault import (
    grant_info,
    receipt_commitment,
    receipt_log_entry,
    verify_grant_receipt,
)
from anagram.network.sharing.app.grants import ThirdPartyWarning
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.proof import verify_bundle
from anagram.sim import generate_community

CHEN_PI = "labs/chen/mei-lin-chen"


@pytest.fixture(scope="module")
def sim(tmp_path_factory):
    return generate_community(tmp_path_factory.mktemp("sim") / "c", seed=0, large_bytes=300_000)


@pytest.fixture
def world(tmp_path, sim):
    net = make_net(tmp_path)
    people = {
        name: net.join(tmp_path / name, f"fake-{name}", name.title()).client
        for name in ("chen", "okafor", "varga")
    }
    return net, people


def sim_file(sim, rel: str) -> Path:
    return sim.out_dir / rel


def commit_chen(sim, chen, third_party=True):
    plan = sim_file(sim, f"{CHEN_PI}/notes/2026-q4-project-plan.md")
    mail = sim_file(sim, f"{CHEN_PI}/mail/collaborator-thread.eml")
    raw = sim_file(sim, "labs/chen/tomas-reyes/raw/G14_movies_stack.mrcs")
    bundle = chen.findings.commit_finding(
        [plan, mail, raw], claim="NBT7 structure at 2.9 A", third_party=[False, third_party, False]
    )
    return bundle.subject.root.hex(), [plan, mail, raw]


def canaries_of(sim, paths):
    rels = {str(p.relative_to(sim.out_dir)) for p in paths}
    return [c["canary"] for c in sim.canaries if c["path"] in rels]


def node_bytes(net) -> bytes:
    out = b""
    for p in sorted(net.home.dir.rglob("*")):
        if p.is_file():
            out += p.read_bytes()
    return out


def test_grant_to_ring_member(world, sim, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root, paths = commit_chen(sim, chen)
    chen.grants.ring_create("lab")
    chen.grants.ring_add("lab", [net.sid("fake-okafor")])
    out = chen.grants.grant(root, ring="lab", warnings_ack=True)
    assert [g["recipient"] for g in out["granted"]] == [net.sid("fake-okafor")]
    inbox = okafor.grants.inbox()
    assert len(inbox) == 1 and inbox[0]["for_this_device"] and inbox[0]["blobs"] == 3
    res = okafor.grants.open_grant(inbox[0]["grant_id"], tmp_path / "okafor-out")
    assert res["verified"] and res["root"] == root and res["owner"] == net.sid("fake-chen")
    assert res["claim"] == "NBT7 structure at 2.9 A"
    got = sorted(Path(f).read_bytes() for f in res["files"])
    assert got == sorted(p.read_bytes() for p in paths)
    # The written proof verifies offline with the opened fields and the files.
    proof = ProofBundle.loads((tmp_path / "okafor-out" / "proof.json").read_text())
    report = verify_bundle(proof, okafor.device.trust(), files=res["files"])
    assert report.ok and report.opened["claim"] == "NBT7 structure at 2.9 A"
    assert len(report.matched_files) == 3


def test_non_member_cannot_read(world, sim):
    net, p = world
    chen, varga = p["chen"], p["varga"]
    root, _ = commit_chen(sim, chen, third_party=False)
    chen.grants.ring_create("lab")
    chen.grants.ring_add("lab", [net.sid("fake-okafor")])
    gid = chen.grants.grant(root, ring="lab")["granted"][0]["grant_id"]
    assert varga.grants.inbox() == []
    with pytest.raises(Exception, match="404"):
        varga.device.http.call("GET", f"/grants/{gid}", auth=True)
    blob = chen.vault.evidence_meta(root)[0]["blob_id"]
    with pytest.raises(Exception, match="404"):
        varga.device.http.call("GET", f"/blobs/{blob}", auth=True)
    with pytest.raises(Exception, match="404"):
        net.transport("GET", f"/blobs/{blob}", None)  # no session
    # Even with the stored envelope, Varga's device key opens no wrap.
    doc = net.vault.get_grant(net.sid("fake-chen"), gid)["grant"]
    vkey = hpke.private_from_bytes(varga.device.x25519_key().private_bytes())
    for w in doc["wraps"]:
        import base64

        with pytest.raises(InvalidTag):
            hpke.open_sealed(
                vkey,
                base64.b64decode(w["ciphertext"]),
                grant_info(bytes.fromhex(gid), bytes.fromhex(w["device"])),
            )


def test_node_holds_no_plaintext(world, sim):
    net, p = world
    chen = p["chen"]
    root, paths = commit_chen(sim, chen)
    chen.grants.ring_create("lab")
    chen.grants.ring_add("lab", [net.sid("fake-okafor"), net.sid("fake-varga")])
    chen.grants.grant(root, ring="lab", warnings_ack=True)
    data = node_bytes(net)
    canaries = canaries_of(sim, paths)
    assert len(canaries) >= 3
    for c in canaries:
        assert c.encode() not in data
    key = chen.grants.content_key(root)
    assert key not in data and key.hex().encode() not in data
    for path in paths:
        sample = path.read_bytes()[:64]
        assert sample not in data
    # Salts (opening data) never reach the node.
    for salt in chen.findings.opening(root).finding.salts.values():
        assert salt not in data and salt.hex().encode() not in data


def test_node_swaps_recipient_key_grant_refused(world, sim):
    net, p = world
    chen = p["chen"]
    root, _ = commit_chen(sim, chen, third_party=False)
    attacker = hpke.public_bytes(hpke.generate()).hex()

    def evil(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if method == "GET" and path.startswith(f"/directory/{net.sid('fake-okafor')}"):
            out["entries"][0]["entry"]["device"]["x25519"] = attacker
        return out

    chen.device.http.transport = evil
    with pytest.raises(LogMisbehaved):
        chen.grants.grant(root, recipients=[net.sid("fake-okafor")])
    assert net.vault.grants_for(net.sid("fake-okafor")) == []

    # A node that adds a device entry that is not in the log is refused too.
    def evil_add(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if method == "GET" and path.startswith(f"/directory/{net.sid('fake-okafor')}"):
            fake = json.loads(json.dumps(out["entries"][0]))
            fake["entry"]["seq"] = 1
            fake["leaf_index"] = out["tree_size"] - 1
            out["entries"].append(fake)
        return out

    chen.device.http.transport = evil_add
    with pytest.raises(LogMisbehaved):
        chen.grants.grant(root, recipients=[net.sid("fake-okafor")])
    assert net.vault.grants_for(net.sid("fake-okafor")) == []


def test_outer_ring_covers_inner_rings(world, sim):
    net, p = world
    chen = p["chen"]
    root, _ = commit_chen(sim, chen, third_party=False)
    chen.grants.ring_create("lab")
    chen.grants.ring_add("lab", [net.sid("fake-okafor")])
    chen.grants.ring_create("collaborators")
    chen.grants.ring_add("collaborators", [net.sid("fake-varga")])
    assert [r["name"] for r in chen.grants.ring_list()] == ["lab", "collaborators"]
    first = chen.grants.grant(root, ring="lab")
    assert {g["recipient"] for g in first["granted"]} == {net.sid("fake-okafor")}
    second = chen.grants.grant(root, ring="collaborators")
    assert {g["recipient"] for g in second["granted"]} == {
        net.sid("fake-okafor"),
        net.sid("fake-varga"),
    }
    assert p["varga"].grants.inbox() and len(p["okafor"].grants.inbox()) == 2
    # "community" expands to all members; a lab member entry expands to the lab.
    chen.grants.ring_create("everyone")
    chen.grants.ring_add("everyone", ["community"])
    third = chen.grants.grant(root, ring="everyone")
    assert {g["recipient"] for g in third["granted"]} == {
        net.sid("fake-okafor"),
        net.sid("fake-varga"),
    }


def test_lab_ring_member(world, sim):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    lab = okafor.labs.lab_create("Okafor Lab")
    # Only a member of the lab sees its members (plan R2, L10).
    okafor.labs.lab_add(lab["lab_id"], chen.device.subject)
    root, _ = commit_chen(sim, chen, third_party=False)
    chen.grants.ring_create("labs")
    chen.grants.ring_add("labs", [lab["lab_id"]])
    out = chen.grants.grant(root, ring="labs")
    assert [g["recipient"] for g in out["granted"]] == [net.sid("fake-okafor")]


def test_grant_receipt_opens_and_verifies(world, sim, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root, _ = commit_chen(sim, chen, third_party=False)
    gid = chen.grants.grant(root, recipients=[net.sid("fake-okafor")])["granted"][0]["grant_id"]
    res = okafor.grants.open_grant(gid, tmp_path / "out")
    saved = json.loads((tmp_path / "out" / "receipt.json").read_text())
    receipt, log = saved["receipt"], saved["log"]
    verify_grant_receipt(receipt)
    assert receipt["recipient"] == net.sid("fake-okafor") and receipt["finding_root"] == root
    assert receipt["sender_key"] == chen.device.device_key().public_bytes().hex()
    assert receipt_commitment(receipt).hex() == res["receipt_commitment"]
    # The log shows only a hash: no recipient, no root, no owner.
    leaf = net.service.entries(log["leaf_index"], log["leaf_index"] + 1)[0]
    assert json.loads(leaf) == receipt_log_entry(receipt)
    for secret in (
        "fake-okafor",
        net.sid("fake-okafor"),
        root,
        receipt["salt"],
        receipt["sender_key"],
    ):
        assert secret not in leaf
    cp = okafor.log.old_checkpoint(log["checkpoint"])
    assert merkle.verify_inclusion(
        merkle.leaf_hash(canonical_json(log["entry"])),
        log["leaf_index"],
        cp.size,
        [bytes.fromhex(h) for h in log["inclusion"]],
        cp.root,
    )
    # A changed receipt (another recipient or date) no longer matches.
    for k, v in (("recipient", net.sid("fake-varga")), ("granted_at", "2020-01-01T00:00:00Z")):
        changed = {**receipt, k: v}
        assert receipt_commitment(changed) != receipt_commitment(receipt)


def test_revoke_makes_new_version(world, sim, tmp_path):
    net, p = world
    chen, okafor, varga = p["chen"], p["okafor"], p["varga"]
    root1, _ = commit_chen(sim, chen, third_party=False)
    chen.grants.ring_create("lab")
    chen.grants.ring_add("lab", [net.sid("fake-okafor"), net.sid("fake-varga")])
    old = {g["recipient"]: g["grant_id"] for g in chen.grants.grant(root1, ring="lab")["granted"]}
    chen.grants.ring_remove("lab", [net.sid("fake-varga")])
    out = chen.grants.revoke(root1, ring="lab")
    root2 = out["root"]
    assert root2 != root1 and chen.grants.content_key(root2) != chen.grants.content_key(root1)
    assert [g["recipient"] for g in out["granted"]] == [net.sid("fake-okafor")]
    assert chen.vault.get(root2).version == 2
    # Okafor reads the new version.
    new_gid = out["granted"][0]["grant_id"]
    assert okafor.grants.open_grant(new_gid, tmp_path / "ok2")["version"] == 2
    # Varga cannot read the new version: no grant, no blob access.
    assert {g["grant_id"] for g in varga.grants.inbox()} == {old[net.sid("fake-varga")]}
    for m in chen.vault.evidence_meta(root2).values():
        with pytest.raises(Exception, match="404"):
            varga.device.http.call("GET", f"/blobs/{m['blob_id']}", auth=True)
    # Documented: access already given cannot be taken back.
    assert varga.grants.open_grant(old[net.sid("fake-varga")], tmp_path / "v1")["version"] == 1


def test_public_publish_verifies_by_anyone(world, sim, tmp_path):
    net, p = world
    chen, varga = p["chen"], p["varga"]
    root, paths = commit_chen(sim, chen, third_party=False)
    with pytest.raises(NodeHTTPError):
        varga.device.http.call("GET", "/public/" + "00" * 16)
    rid = chen.grants.publish(root)["release_id"]
    assert net.transport("GET", "/public", None)["releases"][0]["release_id"] == rid
    res = varga.grants.open_release(rid, tmp_path / "pub")
    assert res["verified"] and res["root"] == root
    assert sorted(Path(f).read_bytes() for f in res["files"]) == sorted(
        x.read_bytes() for x in paths
    )
    # No session needed for the public release and its blobs.
    doc = net.transport("GET", f"/public/{rid}", None)
    assert doc["recipient"] == "public"
    blob = doc["blobs"][0]["blob_id"]
    assert isinstance(net.transport("GET", f"/blobs/{blob}", None), bytes)


def test_third_party_warning_gates_grant_and_publish(world, sim):
    net, p = world
    chen = p["chen"]
    root, _ = commit_chen(sim, chen, third_party=True)
    with pytest.raises(ThirdPartyWarning, match="collaborator-thread.eml"):
        chen.grants.grant(root, recipients=[net.sid("fake-okafor")])
    with pytest.raises(ThirdPartyWarning):
        chen.grants.publish(root)
    assert net.vault.grants_for(net.sid("fake-okafor")) == []
    # The index can set the flag after the commit, per evidence item.
    root2 = chen.findings.commit_finding(
        [sim_file(sim, f"{CHEN_PI}/notes/2026-q4-project-plan.md")]
    )
    root2 = root2.subject.root.hex()
    chen.grants.grant(root2, recipients=[net.sid("fake-okafor")])
    chen.vault.flag_third_party(root2, 0)
    with pytest.raises(ThirdPartyWarning):
        chen.grants.grant(root2, recipients=[net.sid("fake-okafor")])
    assert chen.grants.grant(root2, recipients=[net.sid("fake-okafor")], warnings_ack=True)[
        "granted"
    ]


def test_upload_is_optional(world, sim, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root, _ = commit_chen(sim, chen, third_party=False)
    gid = chen.grants.grant(root, recipients=[net.sid("fake-okafor")], upload=False)["granted"][0][
        "grant_id"
    ]
    res = okafor.grants.open_grant(gid, tmp_path / "o")
    assert res["verified"] and res["files"] == []  # data stays local; the proof still checks
    assert not any(m["blob_id"] for m in chen.vault.evidence_meta(root).values())


def test_new_device_of_recipient_after_sync(world, sim, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root, _ = commit_chen(sim, chen, third_party=False)
    gid = chen.grants.grant(root, recipients=[net.sid("fake-okafor")])["granted"][0]["grant_id"]
    r = net.join(tmp_path / "okafor2", "fake-okafor", "Okafor")
    assert r.status == "pending_device"
    okafor.account.add_device(r.device_request)
    second = net.join(tmp_path / "okafor2", "fake-okafor", "Okafor").client
    with pytest.raises(ClientError, match="sync"):
        second.grants.open_grant(gid, tmp_path / "o2")
    assert chen.grants.sync_grants() == [gid]
    assert chen.grants.sync_grants() == []
    assert second.grants.open_grant(gid, tmp_path / "o2")["verified"]


def test_tampered_payload_parts_are_refused(world, sim, tmp_path):
    net, p = world
    chen, okafor = p["chen"], p["okafor"]
    root, _ = commit_chen(sim, chen, third_party=False)
    gid = chen.grants.grant(root, recipients=[net.sid("fake-okafor")])["granted"][0]["grant_id"]
    # The node swaps a blob for the blob of another evidence slot.
    meta = chen.vault.evidence_meta(root)
    a, b = net.home.dir / "blobs" / meta[0]["blob_id"], net.home.dir / "blobs" / meta[1]["blob_id"]
    da, db = a.read_bytes(), b.read_bytes()
    a.write_bytes(db)
    with pytest.raises(ClientError, match="evidence 0"):
        okafor.grants.open_grant(gid, tmp_path / "x")
    a.write_bytes(da[: len(da) - 20])  # cut
    with pytest.raises(ClientError, match="evidence 0"):
        okafor.grants.open_grant(gid, tmp_path / "y")
    a.write_bytes(da)
    assert okafor.grants.open_grant(gid, tmp_path / "z")["verified"]
    _ = make_net  # imported for other tests
