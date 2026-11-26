"""Attacks from the P1 code review. Each test shows an attack that the verifier
must refuse."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from anagram.core.canonical import canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.chunked import hash_bytes
from anagram.core.crypto.hashing import (
    TAG_EVIDENCE_ROOT,
    TAG_FINDING_ROOT,
    TAG_STREAM_ROOT,
    lp,
    tagged_hash,
)
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.proofs.anchors import AnchorTrust
from anagram.proofs.anchors.fake import FakeAnchor
from anagram.proofs.bundle import EvidenceOpening
from anagram.proofs.log.checkpoint import Checkpoint, sign_checkpoint
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner, add_signature_lines
from anagram.proofs.proof import Trust, build_bundle, verify_bundle
from anagram.proofs.records import (
    KIND_FINDING,
    KIND_STREAM,
    FieldProof,
    SignedSubject,
    check_layout,
    check_schema_layout,
    evidence_fields,
    evidence_opening,
    field_leaf,
    finding_fields,
    finding_opening,
)

T0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
T0_UNIX = int(T0.timestamp())
ORIGIN = "review.anagram.example/log"


def key(label: str) -> SigningKey:
    return SigningKey.from_seed(hashlib.sha256(label.encode()).digest())


OWNER = key("owner")
LOG = NoteSigner(ORIGIN, key("log"))
WITNESSES = [
    NoteSigner(f"review.anagram.example/w{i}", key(f"w{i}"), alg=ALG_COSIGNATURE_V1)
    for i in range(3)
]
ANCHOR_KEYS = [key("anchor 0"), key("anchor 1")]


def logged(subject, finding_openings=(), evidence_openings=(), cosign=None, anchors=None):
    """Put the subject in a one-entry log. cosign: witness index -> unix time.
    anchors: list of (anchor key index, unix time)."""
    entries = [subject.log_entry_bytes()]
    cp = Checkpoint(ORIGIN, 1, merkle.root([merkle.leaf_hash(e) for e in entries]))
    note = sign_checkpoint(cp, LOG)
    cosign = {0: T0_UNIX + 5} if cosign is None else cosign
    note = add_signature_lines(note, [WITNESSES[i].cosign(cp.text(), t) for i, t in cosign.items()])
    anchors = [(0, T0_UNIX + 10)] if anchors is None else anchors
    records = [
        FakeAnchor(ANCHOR_KEYS[i], clock=lambda t=t: t).stamp(cp.digest()) for i, t in anchors
    ]
    submitted = {
        "anchors": records,
        "checkpoint": note,
        "inclusion": [],
        "leaf_index": 0,
        "tree_size": 1,
    }
    return build_bundle(subject, submitted, finding_openings, evidence_openings)


def trust(n_witness=1, threshold=None, min_anchors=1) -> Trust:
    return Trust(
        log_keys=[LOG.verifier],
        witness_keys=[w.verifier for w in WITNESSES[:n_witness]],
        witness_threshold=threshold,
        anchors=AnchorTrust(fake_keys=[k.public_bytes() for k in ANCHOR_KEYS]),
        min_anchors=min_anchors,
    )


def honest():
    ev = evidence_opening(evidence_fields(hash_bytes(b"data"), "text/plain", "a.txt", "file"))
    fields = finding_fields(
        finding_id=bytes(16),
        version=1,
        owner_key=OWNER.public_bytes(),
        created_at=T0,
        evidence_roots=[ev.root()],
        claim="X binds Y",
    )
    fop = finding_opening(fields)
    return fop, ev, SignedSubject.sign(KIND_FINDING, fop.root(), OWNER)


def test_honest_bundle_verifies():
    fop, ev, subject = honest()
    b = logged(
        subject,
        [fop.prove("claim"), fop.prove("evidence.0")],
        [EvidenceOpening(0, (ev.prove("content"),))],
    )
    r = verify_bundle(b, trust())
    assert r.ok, r.summary()


# ------------------------------------------------- 1. duplicate field names


def _hedged_tree(names_values):
    """A malicious owner makes a tree with the given (name, value) leaves, in
    this order, with no check that names are unique."""
    salts = [hashlib.sha256(f"s{i}".encode()).digest() for i in range(len(names_values))]
    leaves = [
        merkle.leaf_hash(field_leaf(n, s, v)) for (n, v), s in zip(names_values, salts, strict=True)
    ]
    sub = merkle.list_subtree(leaves)
    proofs = [
        FieldProof(n, s, v, i, len(leaves), tuple(merkle.inclusion_path(sub, i, len(leaves))))
        # no layout here: the attack adds the layout it wants to show
        for i, ((n, v), s) in enumerate(zip(names_values, salts, strict=True))
    ]
    return leaves, proofs


def _attacker_root(tag, leaves, layout):
    """The root the attacker signs. It uses the layout it will show (no check)."""
    mth = merkle.root(leaves)
    if layout is None:
        return tagged_hash(tag, mth)
    return tagged_hash(tag, lp(canonical_json(list(layout))), mth)


def _attacker_layouts(names):
    """Layouts an attacker can try to show: none, the raw list, the unique list,
    and the unique list padded to the tree size with a spare name."""
    uniq = sorted(set(names))
    padded = sorted(uniq + [f"zz{i}" for i in range(len(names) - len(uniq))])
    return [None, list(names), uniq, padded]


def _with_layout(proofs, layout):
    if layout is None:
        return list(proofs)
    return [replace(p, layout=tuple(layout)) for p in proofs]


@pytest.mark.parametrize(
    ("kind", "tag", "name"),
    [(KIND_FINDING, TAG_FINDING_ROOT, "claim"), (KIND_STREAM, TAG_STREAM_ROOT, "seq")],
)
def test_hedged_field_cannot_open_both(kind, tag, name):
    names_values = [(name, "X binds Y"), (name, "X does not bind Y"), ("owner", None)]
    leaves, proofs = _hedged_tree(names_values)
    # The owner can open at most one of the two values, whatever layout it uses.
    for layout in _attacker_layouts([n for n, _ in names_values]):
        subject = SignedSubject.sign(kind, _attacker_root(tag, leaves, layout), OWNER)
        opened = _with_layout(proofs[:2], layout)
        ok = [verify_bundle(logged(subject, [p]), trust()).ok for p in opened]
        assert not all(ok), layout


def test_duplicate_evidence_content_cannot_open_both():
    _, ev, _ = honest()
    other = hash_bytes(b"other").to_json()
    names_values = [("content", ev.fields["content"]), ("content", other)]
    leaves, proofs = _hedged_tree(names_values)
    for layout in _attacker_layouts(["content", "content"]):
        ev_root = _attacker_root(TAG_EVIDENCE_ROOT, leaves, layout)
        fields = finding_fields(
            finding_id=bytes(16),
            version=1,
            owner_key=OWNER.public_bytes(),
            created_at=T0,
            evidence_roots=[ev_root],
        )
        fop = finding_opening(fields)
        subject = SignedSubject.sign(KIND_FINDING, fop.root(), OWNER)
        ok = []
        for p in _with_layout(proofs, layout):
            b = logged(subject, [fop.prove("evidence.0")], [EvidenceOpening(0, (p,))])
            ok.append(verify_bundle(b, trust()).ok)
        assert not all(ok), layout


def test_layout_rules():
    fop, _, subject = honest()
    p = fop.prove("claim")
    assert p.verify(TAG_FINDING_ROOT, subject.root)
    # Changed layout, short layout, unsorted layout: all fail.
    assert not replace(p, layout=p.layout[:-1]).verify(TAG_FINDING_ROOT, subject.root)
    assert not replace(p, layout=tuple(reversed(p.layout))).verify(TAG_FINDING_ROOT, subject.root)
    assert not replace(p, layout=()).verify(TAG_FINDING_ROOT, subject.root)
    with pytest.raises(FormatError):
        check_schema_layout(TAG_FINDING_ROOT, ["claim", "owner"])
    with pytest.raises(FormatError):
        check_schema_layout(TAG_FINDING_ROOT, sorted([*p.layout, "evidence.2"]))
    with pytest.raises(FormatError):
        check_layout(["a", "evidence.01"])
    check_schema_layout(TAG_FINDING_ROOT, p.layout)
    # The layout is in the JSON form of a field proof.
    assert FieldProof.from_json(p.to_json()) == p


def test_opening_name_must_match_layout_position():
    fop, _, subject = honest()
    p = fop.prove("claim")
    # Rename the claim field to another name that is in the layout.
    renamed = replace(p, name="created_at")
    assert not verify_bundle(logged(subject, [renamed]), trust()).ok


# --------------------------------------------- 2. min_anchors counts duplicates


def test_repeated_anchor_does_not_count_twice():
    _, _, subject = honest()
    b = logged(subject, anchors=[(0, T0_UNIX + 10)])
    b = replace(b, anchors=b.anchors * 2)
    assert not verify_bundle(b, trust(min_anchors=2)).ok
    # Two anchors from the same source at different times are one source too.
    b = logged(subject, anchors=[(0, T0_UNIX + 10), (0, T0_UNIX + 20)])
    assert not verify_bundle(b, trust(min_anchors=2)).ok
    b = logged(subject, anchors=[(0, T0_UNIX + 10), (1, T0_UNIX + 20)])
    assert verify_bundle(b, trust(min_anchors=2)).ok


# ------------------------------------------------- 3. time and thresholds


def test_one_backdated_witness_does_not_set_time():
    _, _, subject = honest()
    early = T0_UNIX - 86400 * 365
    b = logged(
        subject,
        cosign={0: early, 1: T0_UNIX + 5, 2: T0_UNIX + 7},
        anchors=[(0, T0_UNIX + 100)],
    )
    r = verify_bundle(b, trust(n_witness=3, threshold=2, min_anchors=1))
    assert r.ok, r.summary()
    assert r.not_after == datetime.fromtimestamp(T0_UNIX + 5, UTC)
    assert r.witness_time == datetime.fromtimestamp(T0_UNIX + 5, UTC)
    assert r.anchor_time == datetime.fromtimestamp(T0_UNIX + 100, UTC)


def test_one_backdated_anchor_does_not_set_time():
    _, _, subject = honest()
    b = logged(subject, cosign={}, anchors=[(0, T0_UNIX - 9999), (1, T0_UNIX + 30)])
    r = verify_bundle(b, trust(n_witness=0, min_anchors=2))
    assert r.ok, r.summary()
    assert r.not_after == datetime.fromtimestamp(T0_UNIX + 30, UTC)


def test_overflow_cosignature_time_is_invalid():
    _, _, subject = honest()
    b = logged(subject, cosign={0: 2**63 - 1, 1: T0_UNIX + 5})
    r = verify_bundle(b, trust(n_witness=2, threshold=1))
    assert r.ok, r.summary()
    assert r.not_after == datetime.fromtimestamp(T0_UNIX + 5, UTC)
    r = verify_bundle(b, trust(n_witness=2, threshold=2))
    assert not r.ok


# ------------------------------------------------- 5. hostile chunk_size


@pytest.mark.parametrize("chunk_size", [0, -1, 2**40, "x"])
def test_hostile_chunk_size_fails_cleanly(tmp_path, chunk_size):
    content = {**hash_bytes(b"data").to_json(), "chunk_size": chunk_size}
    ev = evidence_opening(evidence_fields(hash_bytes(b"data"), "text/plain", None, "file"))
    ev.fields["content"] = content
    fields = finding_fields(
        finding_id=bytes(16),
        version=1,
        owner_key=OWNER.public_bytes(),
        created_at=T0,
        evidence_roots=[ev.root()],
    )
    fop = finding_opening(fields)
    subject = SignedSubject.sign(KIND_FINDING, fop.root(), OWNER)
    b = logged(subject, [fop.prove("evidence.0")], [EvidenceOpening(0, (ev.prove("content"),))])
    f = tmp_path / "data"
    f.write_bytes(b"data")
    r = verify_bundle(b, trust(), files=[f])
    assert not r.ok
