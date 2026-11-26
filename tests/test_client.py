import base64
import io
import json
import shutil
import zipfile
from dataclasses import replace

import pytest

from anagram.core.crypto import chunked
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import ClientError, LogMisbehaved
from anagram.core.nodeapi import LocalNode
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.log.note import NoteVerifier
from anagram.proofs.node.routes import parse_tile_index
from anagram.proofs.proof import Trust, verify_bundle
from anagram.proofs.records import FieldProof, Link, SignedSubject
from anagram.shell.client import Client
from anagram.shell.node.home import NodeHome


@pytest.fixture
def client(tmp_path):
    return Client.init(tmp_path / "home")


@pytest.fixture
def files(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    (d / "notes.txt").write_text("Protein X binds Y at pH 6.\n")
    (d / "figure3.png").write_bytes(png_bytes())
    (d / "talk.pptx").write_bytes(pptx_bytes())
    (d / "thread.eml").write_bytes(eml_bytes())
    (d / "raw.bin").write_bytes(bytes(range(256)) * 40)
    return d


def png_bytes() -> bytes:
    import struct
    import zlib

    def chunk(kind, data):
        c = kind + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    raw = b"\x00\xff\x00\x00"
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def pptx_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("ppt/slides/slide1.xml", "<p:sld>Result: X binds Y</p:sld>")
    return buf.getvalue()


def eml_bytes() -> bytes:
    return (
        b"From: a@example.org\r\nTo: b@example.org\r\nSubject: result\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\nX binds Y. Do not share.\r\n"
    )


def test_commit_and_verify(client, files):
    paths = sorted(files.iterdir())
    bundle = client.findings.commit_finding(paths, claim="Protein X binds Y")
    report = verify_bundle(bundle, client.device.trust())
    assert report.ok, report.summary()
    assert report.not_after is not None
    # The public log entry has no root, no salt, no claim.
    entry = client.node.service.store.entry(bundle.log.leaf_index).decode()
    assert bundle.subject.root.hex() not in entry and "Protein" not in entry
    # Round trip through JSON.
    again = ProofBundle.loads(bundle.dumps())
    assert verify_bundle(again, client.device.trust()).ok
    # The owner can read back all opening data.
    doc = client.findings.opening(bundle.subject.root.hex())
    assert doc.finding.fields["claim"] == "Protein X binds Y"
    assert {e.fields["media_type"] for e in doc.evidence} == {
        "application/octet-stream",
        "image/png",
        "text/plain",
        "message/rfc822",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }


def test_any_media_type_prove_file(client, files, tmp_path):
    paths = sorted(files.iterdir())
    bundle = client.findings.commit_finding(paths)
    ref = bundle.subject.root.hex()[:12]
    for p in paths:
        public_copy = tmp_path / ("copy-" + p.name)
        shutil.copy(p, public_copy)
        proof = client.findings.prove_file(ref, public_copy)
        assert proof.sealed_opening is None
        report = verify_bundle(proof, client.device.trust(), files=[public_copy])
        assert report.ok, report.summary()
        # Only the content field of one evidence item is open.
        assert list(report.opened) == [f"evidence.{report.matched_files[str(public_copy)]}"]
        assert all(set(f) == {"content"} for f in report.evidence.values())


def test_prove_file_negative(client, files, tmp_path):
    bundle = client.findings.commit_finding([files / "notes.txt"])
    changed = tmp_path / "notes.txt"
    changed.write_text("Protein X binds Z at pH 6.\n")
    with pytest.raises(ClientError):
        client.findings.prove_file(bundle.subject.root.hex(), changed)
    # A valid file proof does not match a changed public copy.
    proof = client.findings.prove_file(bundle.subject.root.hex(), files / "notes.txt")
    report = verify_bundle(proof, client.device.trust(), files=[changed])
    assert not report.ok


def test_changed_claim_fails(client, files):
    bundle = client.findings.commit_finding([files / "notes.txt"], claim="X binds Y")
    pub = client.findings.public_bundle(bundle.subject.root.hex(), ["claim", "created_at", "owner"])
    report = verify_bundle(pub, client.device.trust())
    assert report.ok and report.opened["claim"] == "X binds Y"
    claim = next(f for f in pub.finding_openings if f.name == "claim")
    forged = replace(claim, value="X binds Z")
    bad = replace(pub, finding_openings=(forged,))
    assert not verify_bundle(bad, client.device.trust()).ok


def test_changed_evidence_root_fails(client, files):
    bundle = client.findings.commit_finding([files / "notes.txt"])
    pub = client.findings.prove_file(bundle.subject.root.hex(), files / "notes.txt")
    ev = pub.evidence_openings[0]
    content = ev.fields[0]
    digest = chunked.hash_bytes(b"other bytes").to_json()
    forged = replace(ev, fields=(FieldProof(**{**content.__dict__, "value": digest}),))
    assert not verify_bundle(replace(pub, evidence_openings=(forged,)), client.device.trust()).ok


def test_wrong_keys_fail(client, files):
    bundle = client.findings.commit_finding([files / "notes.txt"])
    trust = client.device.trust()
    other_log = NoteVerifier(trust.log_keys[0].name, 1, SigningKey.generate().public_bytes())
    assert not verify_bundle(bundle, Trust([other_log], anchors=trust.anchors)).ok
    # Another person's key on the same root and signature.
    s = bundle.subject
    thief = SignedSubject(s.kind, s.root, SigningKey.generate().public_bytes(), s.signature)
    assert not verify_bundle(replace(bundle, subject=thief), trust).ok
    # Unpinned witness: threshold not met.
    no_w = Trust(trust.log_keys, [], witness_threshold=1, anchors=trust.anchors)
    assert not verify_bundle(bundle, no_w).ok
    # Unpinned anchor key: no valid anchor.
    no_a = Trust(trust.log_keys, trust.witness_keys)
    assert not verify_bundle(bundle, no_a).ok


def test_backdated_checkpoint_fails(client, files):
    first = client.findings.commit_finding([files / "notes.txt"])
    second = client.findings.commit_finding([files / "raw.bin"])
    trust = client.device.trust()
    # Reuse the older checkpoint's anchors (an earlier time) on the newer checkpoint.
    moved = replace(second, anchors=first.anchors)
    assert not verify_bundle(moved, trust).ok
    # Change the anchor time.
    rec = dict(second.anchors[0])
    rec["time"] = "2020-01-01T00:00:00Z"
    assert not verify_bundle(replace(second, anchors=(rec,)), trust).ok
    # Change the cosignature timestamp inside the checkpoint note.
    note = second.log.checkpoint
    body, sigs = note.split("\n\n")
    lines = sigs.strip("\n").split("\n")
    name, blob = lines[1][2:].split(" ")
    raw = bytearray(base64.b64decode(blob))
    raw[4:12] = (1_500_000_000).to_bytes(8, "big")
    lines[1] = f"— {name} {base64.b64encode(bytes(raw)).decode()}"
    forged_note = body + "\n\n" + "\n".join(lines) + "\n"
    forged = replace(second, log=replace(second.log, checkpoint=forged_note))
    assert not verify_bundle(forged, trust).ok
    # Use the old checkpoint for the new entry.
    old_cp = replace(second, log=replace(second.log, checkpoint=first.log.checkpoint))
    assert not verify_bundle(old_cp, trust).ok


def test_verify_offline_after_node_deleted(client, files, tmp_path):
    bundle = client.findings.commit_finding([files / "notes.txt"], claim="c")
    saved = tmp_path / "proof.json"
    saved.write_text(bundle.dumps())
    trust = client.device.trust()
    client.node.service.store.close()
    shutil.rmtree(client.home / "node")
    assert not (client.home / "node").exists()
    report = verify_bundle(ProofBundle.loads(saved.read_text()), trust)
    assert report.ok, report.summary()


def test_supersedes_and_links(client, files):
    v1 = client.findings.commit_finding([files / "notes.txt"], claim="first")
    v2 = client.findings.commit_finding(
        [files / "figure3.png"],
        claim="second",
        links=[Link("supersedes", v1.subject.root), Link("builds_on", v1.subject.root)],
    )
    d1 = client.findings.opening(v1.subject.root.hex()).finding.fields
    d2 = client.findings.opening(v2.subject.root.hex()).finding.fields
    assert d2["finding_id"] == d1["finding_id"] and d2["version"] == 2
    assert d2["links.0"] == {"target": v1.subject.root.hex(), "type": "supersedes"}
    # A finding_id reference gives the latest version.
    assert client.vault.find(d1["finding_id"][:10]).version == 2
    with pytest.raises(ClientError):
        client.findings.commit_finding([], claim="x", links=[Link("supersedes", bytes(32))])


def test_client_detects_forked_log(client, files):
    client.findings.commit_finding([files / "notes.txt"])
    client.findings.commit_finding([files / "raw.bin"])
    # The operator replaces its log with a different history, same keys.
    nh = NodeHome(client.home / "node")
    client.node.service.store.close()
    (client.home / "node" / "log.sqlite").unlink()
    (client.home / "node" / "witness.sqlite").unlink()
    forked = nh.service()
    for i in range(3):
        forked.store.append(json.dumps({"x": i}).encode())
    client.device.node = LocalNode(forked)
    with pytest.raises(LogMisbehaved):
        client.findings.commit_finding([files / "figure3.png"])


def test_large_file_through_client(client, tmp_path, monkeypatch):
    monkeypatch.setattr(chunked, "CHUNK_SIZE", 4096)
    big = tmp_path / "scan.tiff"
    with open(big, "wb") as f:
        for i in range(64):
            f.write(bytes([i]) * 65536)
    bundle = client.findings.commit_finding([big])
    doc = client.findings.opening(bundle.subject.root.hex())
    assert doc.evidence[0].fields["content"]["chunk_size"] == 4096
    monkeypatch.setattr(chunked, "CHUNK_SIZE", 1 << 20)
    proof = client.findings.prove_file(bundle.subject.root.hex(), big)
    assert verify_bundle(proof, client.device.trust(), files=[big]).ok


def test_http_node(net, tmp_path, files):
    tc = net.tc
    c = net.join(tmp_path / "home", "fake-http-node").client
    b1 = c.findings.commit_finding([files / "notes.txt"])
    b2 = c.findings.commit_finding([files / "raw.bin"], claim="two")
    assert verify_bundle(b1, c.device.trust()).ok and verify_bundle(b2, c.device.trust()).ok
    assert tc.get("/log/checkpoint").json()["tree_size"] == 3  # key binding + 2 findings
    assert tc.post("/log/entries", json={"entry": {"kind": "x"}}).status_code == 401
    auth = {"Authorization": f"Bearer {c.node.token}"}
    assert tc.post("/log/entries", json={"entry": {"kind": "x"}}, headers=auth).status_code == 400
    tile = tc.get("/tile/0/000.p/2")
    assert tile.status_code == 200 and len(tile.content) == 64
    bundle = tc.get("/tile/entries/000.p/2")
    assert bundle.status_code == 200
    assert tc.get("/tile/0/000").status_code == 404
    assert parse_tile_index("x001/x234/067.p/3") == (1234067, 3)
