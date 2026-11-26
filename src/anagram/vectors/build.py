"""Make the test vectors in spec/vectors/. All inputs are fixed, so the output is
the same on each run.

    uv run python -m anagram.vectors.build spec/vectors

Each vector file holds inputs and expected outputs. An independent
implementation must give the same outputs from the same inputs.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.chunked import hash_bytes
from anagram.core.crypto.hashing import ALL_TAGS
from anagram.core.crypto.signing import SigningKey
from anagram.proofs.anchors.fake import FakeAnchor
from anagram.proofs.bundle import EvidenceOpening, ProofBundle
from anagram.proofs.log.checkpoint import Checkpoint, sign_checkpoint
from anagram.proofs.log.note import ALG_COSIGNATURE_V1, NoteSigner, add_signature_lines
from anagram.proofs.proof import build_bundle
from anagram.proofs.records import (
    KIND_FINDING,
    KIND_STREAM,
    Link,
    OpeningDocument,
    SignedSubject,
    evidence_fields,
    evidence_opening,
    field_leaf,
    finding_fields,
    finding_opening,
    stream_checkpoint_fields,
    stream_opening,
)
from anagram.proofs.sealed import seal_opening
from anagram.vectors import identity as identity_vectors
from anagram.vectors import lab as lab_vectors
from anagram.vectors import sharing as sharing_vectors
from anagram.vectors import trust as trust_vectors
from anagram.vectors import vault as vault_vectors
from anagram.vectors.cli import output_dir

T0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
T0_UNIX = int(T0.timestamp())
ORIGIN = "vectors.anagram.example/log"


def seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram test vector seed: {label}".encode()).digest()


def salt_fn(prefix: str):
    """Fixed salts: SHA-256("anagram test vector salt: <prefix>/<n>")."""
    counter = iter(range(1000))

    def make() -> bytes:
        return hashlib.sha256(
            f"anagram test vector salt: {prefix}/{next(counter)}".encode()
        ).digest()

    return make


def _opening_vector(op) -> dict:
    return {
        "fields": op.fields,
        "layout_canonical": canonical_json(op.names()).decode(),
        "leaves": {n: field_leaf(n, op.salts[n], op.fields[n]).hex() for n in op.names()},
        "mth": merkle.root(op.leaf_hashes()).hex(),
        "order": op.names(),
        "root": op.root().hex(),
        "salts": {n: op.salts[n].hex() for n in op.names()},
    }


def canonical_vectors() -> dict:
    cases = [
        {"b": 1, "a": [True, False, None]},
        {"€": "$", "\r": "\n", "1": {"z": "", "y": -9007199254740991}},
        '\u0000\u001f"\\\u007f \U0001f600',
        {"דּ": 0, "\U0001f600": 1, "a": 2},
    ]
    return {
        "description": "Canonical JSON (RFC 8785 subset, no floats).",
        "valid": [{"input": c, "canonical_utf8_hex": canonical_json(c).hex()} for c in cases],
        "invalid_json_text": ["1.5", "[1e3]", '{"a":1,"a":2}', "9007199254740992", "NaN"],
    }


def merkle_vectors() -> dict:
    data = [f"leaf {i}".encode() for i in range(7)]
    hashes = [merkle.leaf_hash(d) for d in data]
    sub = merkle.list_subtree(hashes)
    return {
        "description": "RFC 6962 Merkle tree hash, inclusion and consistency proofs.",
        "leaves_utf8": [d.decode() for d in data],
        "roots": {str(n): merkle.root(hashes[:n]).hex() for n in range(0, 8)},
        "inclusion": [
            {"index": i, "size": 7, "path": [h.hex() for h in merkle.inclusion_path(sub, i, 7)]}
            for i in (0, 3, 6)
        ],
        "consistency": [
            {"old": m, "new": 7, "path": [h.hex() for h in merkle.consistency_path(sub, m, 7)]}
            for m in (1, 3, 4, 6)
        ],
    }


def content_vectors() -> dict:
    out = []
    for size, chunk in ((0, 16), (1, 16), (16, 16), (50, 16), (1000, 1 << 20)):
        data = bytes(i % 251 for i in range(size))
        out.append(
            {
                "data": f"bytes(i % 251 for i in range({size}))",
                "chunk_size": chunk,
                "content": hash_bytes(data, chunk).to_json(),
            }
        )
    return {"description": "Chunked content digest.", "cases": out}


def build_all() -> dict[str, dict]:
    owner = SigningKey.from_seed(seed("owner"))
    vault_key = seed("vault key")

    ev_ops = []
    files = [
        (b"Protein X binds Y at pH 6.\n", "text/plain", "notes.txt"),
        (bytes(range(256)) * 3, "image/png", "figure3.png"),
    ]
    for i, (data, mt, name) in enumerate(files):
        f = evidence_fields(hash_bytes(data, 64), mt, name, "file")
        ev_ops.append(evidence_opening(f, salt_fn(f"evidence/{i}")))

    prev_root = hashlib.sha256(b"anagram test vector: previous version").digest()
    links = [
        Link("supersedes", prev_root),
        Link("builds_on", hashlib.sha256(b"anagram test vector: other finding").digest()),
        Link("includes", hashlib.sha256(b"anagram test vector: figure finding").digest()),
    ]
    ff = finding_fields(
        finding_id=seed("finding id")[:16],
        version=2,
        owner_key=owner.public_bytes(),
        created_at=T0,
        evidence_roots=[e.root() for e in ev_ops],
        claim="Protein X binds Y",
        links=links,
    )
    fop = finding_opening(ff, salt_fn("finding"))
    subject = SignedSubject.sign(KIND_FINDING, fop.root(), owner)

    sf = stream_checkpoint_fields(
        stream_id=seed("stream id")[:16],
        seq=1,
        prev=hashlib.sha256(b"anagram test vector: stream checkpoint 0").digest(),
        start=10,
        item_roots=[e.root() for e in ev_ops],
        owner_key=owner.public_bytes(),
        created_at=T0,
    )
    sop = stream_opening(sf, salt_fn("stream"))
    stream_subject = SignedSubject.sign(KIND_STREAM, sop.root(), owner)

    # A tiny log: three filler entries, then the finding entry.
    log_signer = NoteSigner(ORIGIN, SigningKey.from_seed(seed("log")))
    witness = NoteSigner(
        "vectors.anagram.example/witness",
        SigningKey.from_seed(seed("witness")),
        alg=ALG_COSIGNATURE_V1,
    )
    entries = [
        canonical_json(SignedSubject.sign(KIND_FINDING, seed(f"filler {i}"), owner).log_entry())
        for i in range(3)
    ]
    entries.append(subject.log_entry_bytes())
    hashes = [merkle.leaf_hash(e) for e in entries]
    cp = Checkpoint(ORIGIN, len(entries), merkle.root(hashes))
    note = sign_checkpoint(cp, log_signer)
    note = add_signature_lines(note, [witness.cosign(cp.text(), T0_UNIX + 5)])
    anchor_key = SigningKey.from_seed(seed("fake anchor"))
    anchor = FakeAnchor(anchor_key, clock=lambda: T0_UNIX + 10).stamp(cp.digest())

    doc = OpeningDocument(fop, ev_ops)
    sealed = seal_opening(vault_key, fop.root(), doc, nonce=seed("nonce")[:12])
    submitted = {
        "anchors": [anchor],
        "checkpoint": note,
        "inclusion": [h.hex() for h in merkle.inclusion_path(merkle.list_subtree(hashes), 3, 4)],
        "leaf_index": 3,
        "tree_size": 4,
    }
    bundle = build_bundle(
        subject,
        submitted,
        finding_openings=[fop.prove("claim"), fop.prove("evidence.0")],
        evidence_openings=[EvidenceOpening(0, (ev_ops[0].prove("content"),))],
        sealed_opening=sealed,
    )
    ProofBundle.from_json(bundle.to_json())

    keys = {
        "owner_seed": seed("owner").hex(),
        "owner_public": owner.public_bytes().hex(),
        "vault_key": vault_key.hex(),
        "log_vkey": log_signer.vkey(),
        "witness_vkey": witness.vkey(),
        "fake_anchor_public": anchor_key.public_bytes().hex(),
    }
    return {
        "tags.json": {"description": "Domain tags (locked).", "tags": list(ALL_TAGS)},
        "canonical-json.json": canonical_vectors(),
        "merkle.json": merkle_vectors(),
        "content-digest.json": content_vectors(),
        "evidence.json": {
            "description": "Evidence records with fixed salts.",
            "files": [
                {"data_hex": d.hex(), "media_type": m, "name": n, "chunk_size": 64}
                for d, m, n in files
            ],
            "records": [_opening_vector(e) for e in ev_ops],
        },
        "finding.json": {
            "description": "Finding envelope with all three link types, fixed salts.",
            "keys": keys,
            "envelope": _opening_vector(fop),
            "subject": subject.to_json(),
            "log_entry": subject.log_entry(),
            "log_entry_canonical": subject.log_entry_bytes().decode(),
        },
        "stream-checkpoint.json": {
            "description": "Stream checkpoint over the two evidence roots.",
            "item_roots": [e.root().hex() for e in ev_ops],
            "envelope": _opening_vector(sop),
            "subject": stream_subject.to_json(),
        },
        "checkpoint.json": {
            "description": "C2SP checkpoint with log signature and witness cosignature.",
            "log_entries_canonical": [e.decode() for e in entries],
            "checkpoint_text": cp.text(),
            "checkpoint_digest": cp.digest().hex(),
            "note": note,
            "keys": keys,
        },
        "identity.json": identity_vectors.build(),
        "vault.json": vault_vectors.build(),
        "lab.json": lab_vectors.build(),
        "sharing.json": sharing_vectors.build(),
        "trust-policy.json": trust_vectors.build(),
        "proof-bundle.json": {
            "description": "Full proof bundle. verify_bundle must accept it with these keys.",
            "keys": keys,
            "expected_not_after": "2026-10-15T12:00:05Z",
            "bundle": bundle.to_json(),
        },
    }


def write(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, obj in build_all().items():
        (directory / name).write_text(
            json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )


if __name__ == "__main__":  # pragma: no cover
    write(output_dir(None, prog="python -m anagram.vectors.build", description=__doc__))
