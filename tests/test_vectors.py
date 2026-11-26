"""The spec test vectors must match the code, and must verify on their own."""

import json
from pathlib import Path

import pytest

from anagram.core import canonical
from anagram.core.crypto import merkle
from anagram.core.crypto.chunked import ContentDigest, hash_bytes
from anagram.core.crypto.hashing import (
    TAG_EVIDENCE_ROOT,
    TAG_FINDING_ROOT,
    TAG_STREAM_ROOT,
    lp,
    tagged_hash,
)
from anagram.proofs.anchors import AnchorTrust
from anagram.proofs.bundle import ProofBundle
from anagram.proofs.log.checkpoint import open_checkpoint
from anagram.proofs.log.note import NoteVerifier
from anagram.proofs.proof import Trust, verify_bundle
from anagram.proofs.records import Opening, SignedSubject, field_leaf
from anagram.proofs.sealed import unseal_opening
from anagram.vectors.build import build_all

VEC = Path(__file__).parent.parent / "spec" / "vectors"


def load(name):
    return json.loads((VEC / name).read_text())


@pytest.mark.parametrize("name", sorted(build_all()))
def test_vectors_are_current(name):
    assert load(name) == json.loads(json.dumps(build_all()[name]))


def test_canonical_vectors():
    v = load("canonical-json.json")
    for case in v["valid"]:
        assert canonical.canonical_json(case["input"]).hex() == case["canonical_utf8_hex"]
    for text in v["invalid_json_text"]:
        with pytest.raises(canonical.CanonicalError):
            canonical.loads(text)


def test_merkle_vectors():
    v = load("merkle.json")
    hashes = [merkle.leaf_hash(s.encode()) for s in v["leaves_utf8"]]
    for n, root in v["roots"].items():
        assert merkle.root(hashes[: int(n)]).hex() == root
    for c in v["inclusion"]:
        path = [bytes.fromhex(h) for h in c["path"]]
        assert merkle.verify_inclusion(
            hashes[c["index"]], c["index"], c["size"], path, bytes.fromhex(v["roots"]["7"])
        )
    for c in v["consistency"]:
        path = [bytes.fromhex(h) for h in c["path"]]
        assert merkle.verify_consistency(
            c["old"],
            c["new"],
            path,
            bytes.fromhex(v["roots"][str(c["old"])]),
            bytes.fromhex(v["roots"]["7"]),
        )


def test_content_vectors():
    for c in load("content-digest.json")["cases"]:
        size = c["content"]["size"]
        data = bytes(i % 251 for i in range(size))
        assert hash_bytes(data, c["chunk_size"]) == ContentDigest.from_json(c["content"])


def check_opening(vec, tag):
    op = Opening(tag, vec["fields"], {k: bytes.fromhex(s) for k, s in vec["salts"].items()})
    assert op.names() == vec["order"]
    for n in op.names():
        assert field_leaf(n, op.salts[n], op.fields[n]).hex() == vec["leaves"][n]
    assert canonical.canonical_json(op.names()).decode() == vec["layout_canonical"]
    mth = merkle.root(op.leaf_hashes())
    assert mth.hex() == vec["mth"]
    # root = tagged_hash(tag, lp(canonical_json(layout)) || MTH), written out here.
    layout = vec["layout_canonical"].encode()
    assert tagged_hash(tag, lp(layout), mth).hex() == vec["root"]
    assert op.root().hex() == vec["root"]
    return op


def test_evidence_and_finding_vectors():
    ev = load("evidence.json")
    for f, rec in zip(ev["files"], ev["records"], strict=True):
        check_opening(rec, TAG_EVIDENCE_ROOT)
        assert ContentDigest.from_json(rec["fields"]["content"]) == hash_bytes(
            bytes.fromhex(f["data_hex"]), f["chunk_size"]
        )
    fv = load("finding.json")
    op = check_opening(fv["envelope"], TAG_FINDING_ROOT)
    assert [op.fields[f"links.{i}"]["type"] for i in range(3)] == [
        "supersedes",
        "builds_on",
        "includes",
    ]
    subject = SignedSubject.from_json(fv["subject"])
    assert subject.signature_ok() and subject.root == op.root()
    assert subject.log_entry() == fv["log_entry"]
    assert canonical.canonical_json(fv["log_entry"]).decode() == fv["log_entry_canonical"]

    sv = load("stream-checkpoint.json")
    sop = check_opening(sv["envelope"], TAG_STREAM_ROOT)
    st = SignedSubject.from_json(sv["subject"])
    assert st.signature_ok() and st.root == sop.root()


def test_checkpoint_vector():
    v = load("checkpoint.json")
    keys = v["keys"]
    vc = open_checkpoint(
        v["note"],
        [NoteVerifier.parse(keys["log_vkey"])],
        [NoteVerifier.parse(keys["witness_vkey"])],
    )
    assert vc.checkpoint.text() == v["checkpoint_text"]
    assert vc.checkpoint.digest().hex() == v["checkpoint_digest"]
    hashes = [merkle.leaf_hash(e.encode()) for e in v["log_entries_canonical"]]
    assert merkle.root(hashes) == vc.checkpoint.root
    assert len(vc.cosignatures) == 1


def test_proof_bundle_vector():
    v = load("proof-bundle.json")
    keys = v["keys"]
    bundle = ProofBundle.from_json(v["bundle"])
    assert bundle.to_json() == v["bundle"]
    trust = Trust(
        log_keys=[NoteVerifier.parse(keys["log_vkey"])],
        witness_keys=[NoteVerifier.parse(keys["witness_vkey"])],
        anchors=AnchorTrust(fake_keys=[bytes.fromhex(keys["fake_anchor_public"])]),
    )
    report = verify_bundle(bundle, trust)
    assert report.ok, report.summary()
    assert report.not_after.strftime("%Y-%m-%dT%H:%M:%SZ") == v["expected_not_after"]
    assert report.opened["claim"] == "Protein X binds Y"
    doc = unseal_opening(bytes.fromhex(keys["vault_key"]), bundle.sealed_opening)
    assert doc.finding.root() == bundle.subject.root
    assert len(doc.evidence) == 2
