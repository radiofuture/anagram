from datetime import UTC, datetime

import pytest
from cryptography.exceptions import InvalidTag

from anagram.core import canonical
from anagram.core.crypto import aead
from anagram.core.crypto.chunked import hash_bytes
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.proofs.records import (
    Link,
    OpeningDocument,
    SignedSubject,
    evidence_fields,
    evidence_opening,
    finding_fields,
    finding_opening,
)
from anagram.proofs.sealed import seal_opening, unseal_opening

T0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)


def test_canonical_basic():
    v = {"b": [1, True, None, "x"], "a": {"z": -5, "y": ""}}
    assert canonical.canonical_json(v) == b'{"a":{"y":"","z":-5},"b":[1,true,null,"x"]}'


def test_canonical_rfc8785_escapes_and_unicode():
    s = '€$\u000f\nA\'B"\\\\"/'
    assert canonical.canonical_json(s) == ('"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"').encode()
    assert canonical.canonical_json("\x7f ") == '"\x7f "'.encode()


def test_canonical_utf16_key_order():
    # RFC 8785 3.2.3: sort by UTF-16 code units. U+1F600 (surrogates D83D..) sorts
    # before U+FB33 in UTF-16 but after it in code points.
    v = {"דּ": 1, "\U0001f600": 2, "a": 3}
    out = canonical.canonical_json(v).decode()
    assert out.index("a") < out.index("\U0001f600") < out.index("דּ")


@pytest.mark.parametrize("bad", [1.5, float("nan"), 2**53, -(2**53), {1: 2}, b"x", "\ud800"])
def test_canonical_rejects(bad):
    with pytest.raises(canonical.CanonicalError):
        canonical.canonical_json(bad)


def test_loads_strict():
    assert canonical.loads_canonical(b'{"a":1}') == {"a": 1}
    with pytest.raises(canonical.CanonicalError):
        canonical.loads_canonical(b'{"a": 1}')
    with pytest.raises(canonical.CanonicalError):
        canonical.loads(b'{"a":1,"a":2}')
    with pytest.raises(canonical.CanonicalError):
        canonical.loads(b'{"a":1.0}')
    with pytest.raises(canonical.CanonicalError):
        canonical.loads(b"[NaN]")


def make_finding(claim="Protein X binds Y", n_evidence=3):
    key = SigningKey.from_seed(bytes(32))
    evs = [
        evidence_opening(
            evidence_fields(hash_bytes(f"data {i}".encode()), "text/plain", f"f{i}.txt", "file")
        )
        for i in range(n_evidence)
    ]
    fields = finding_fields(
        finding_id=bytes(16),
        version=1,
        owner_key=key.public_bytes(),
        created_at=T0,
        evidence_roots=[e.root() for e in evs],
        claim=claim,
    )
    return key, finding_opening(fields), evs


def test_selective_opening():
    _, f, evs = make_finding()
    root = f.root()
    for name in f.names():
        p = f.prove(name)
        assert p.verify(f.root_tag, root)
    p = f.prove("claim")
    tampered = type(p)(p.name, p.salt, "Protein X binds Z", p.index, p.size, p.path)
    assert not tampered.verify(f.root_tag, root)
    wrong_salt = type(p)(p.name, bytes(32), p.value, p.index, p.size, p.path)
    assert not wrong_salt.verify(f.root_tag, root)
    # The evidence root in the finding equals the root of the evidence opening.
    assert f.prove("evidence.1").value == evs[1].root().hex()


def test_salts_hide_equal_values():
    _, a, ea = make_finding()
    _, b, eb = make_finding()
    # Same file bytes, different salts: different evidence roots and finding roots.
    assert ea[0].fields == eb[0].fields
    assert ea[0].root() != eb[0].root()
    assert a.root() != b.root()


def test_finding_rules():
    key = SigningKey.from_seed(bytes(32))
    common = dict(finding_id=bytes(16), owner_key=key.public_bytes(), created_at=T0)
    with pytest.raises(FormatError):
        finding_fields(version=2, evidence_roots=[], **common)
    with pytest.raises(FormatError):
        Link("cites", bytes(32))
    ok = finding_fields(
        version=2,
        evidence_roots=[],
        links=[Link("supersedes", bytes(32)), Link("includes", b"\x01" * 32)],
        **common,
    )
    assert ok["links.1"] == {"target": "01" * 32, "type": "includes"}


def test_subject_signature_and_log_entry():
    key, f, _ = make_finding()
    subj = SignedSubject.sign("finding", f.root(), key)
    assert subj.signature_ok()
    other = SigningKey.from_seed(b"\x01" * 32)
    forged = SignedSubject("finding", f.root(), other.public_bytes(), subj.signature)
    assert not forged.signature_ok()
    entry = subj.log_entry()
    assert set(entry) == {"commitment", "kind", "schema"}
    assert f.root().hex() not in canonical.canonical_json(entry).decode()
    assert SignedSubject.from_json(subj.to_json()) == subj


def test_sealed_opening_round_trip():
    _, f, evs = make_finding()
    doc = OpeningDocument(f, evs)
    key = aead.new_key()
    sealed = seal_opening(key, f.root(), doc)
    back = unseal_opening(key, sealed)
    assert back.finding.root() == f.root()
    assert [e.root() for e in back.evidence] == [e.root() for e in evs]
    with pytest.raises(FormatError):
        unseal_opening(aead.new_key(), sealed)
    moved = {**sealed, "subject_root": "00" * 32}
    with pytest.raises(InvalidTag):
        unseal_opening(key, moved)
