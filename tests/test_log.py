import base64

import pytest

from anagram.core.crypto import merkle
from anagram.core.crypto.signing import SigningKey
from anagram.proofs.log.checkpoint import Checkpoint, open_checkpoint, sign_checkpoint
from anagram.proofs.log.note import (
    ALG_COSIGNATURE_V1,
    NoteError,
    NoteSigner,
    NoteVerifier,
    add_signature_lines,
    parse_note,
    verify_cosignature,
)
from anagram.proofs.log.store import SQLiteLog, tile_index_path, tile_path
from anagram.proofs.log.witness import ForkDetected, Witness, WitnessConflict, WitnessRefused

ORIGIN = "example.org/anagram-test-log"


def test_signed_note_matches_go_sumdb_note_vector():
    # Test vector from golang.org/x/mod/sumdb/note (note_test.go).
    seed = base64.b64decode("AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz")[1:]
    signer = NoteSigner("PeterNeumann", SigningKey.from_seed(seed))
    assert signer.vkey() == "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
    text = (
        "If you think cryptography is the answer to your problem,\n"
        "then you don't know what your problem is.\n"
    )
    assert signer.signature_line(text) == (
        "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXg"
        "KvqfqdngotpRZb6KE6RyyBwJnAM=\n"
    )
    assert NoteVerifier.parse(signer.vkey()) == signer.verifier


def test_verifier_parse_handles_plus_in_base64():
    for i in range(200):
        signer = NoteSigner("a.example/log", SigningKey.from_seed(i.to_bytes(32, "big")))
        if "+" in signer.vkey().split("+", 2)[2]:
            assert NoteVerifier.parse(signer.vkey()) == signer.verifier
            return
    raise AssertionError("no key with + in base64 found")


def test_verifier_parse_rejects_bad_hash():
    signer = NoteSigner("a.example/log", SigningKey.from_seed(bytes(32)))
    name, _, enc = signer.vkey().split("+")
    with pytest.raises(NoteError):
        NoteVerifier.parse(f"{name}+00000000+{enc}")


@pytest.fixture
def log(tmp_path):
    return SQLiteLog(tmp_path / "log.sqlite")


def entries(n):
    return [f"entry {i}".encode() for i in range(n)]


def test_store_matches_reference(log):
    data = entries(70)
    hashes = [merkle.leaf_hash(d) for d in data]
    for i, d in enumerate(data):
        assert log.append(d) == i
    for size in range(0, 71):
        assert log.root(size) == merkle.root(hashes[:size])
    for size in (1, 2, 7, 64, 70):
        root = log.root(size)
        for i in range(size):
            assert merkle.verify_inclusion(hashes[i], i, size, log.inclusion_proof(i, size), root)
        for old in range(0, size + 1):
            p = log.consistency_proof(old, size)
            assert merkle.verify_consistency(old, size, p, log.root(old), root)


def test_store_persists(tmp_path):
    a = SQLiteLog(tmp_path / "l.sqlite")
    for d in entries(5):
        a.append(d)
    root = a.root()
    a.close()
    b = SQLiteLog(tmp_path / "l.sqlite")
    assert b.size() == 5 and b.root() == root


def test_tiles(log):
    for d in entries(256 * 2 + 3):
        log.append(d)
    t0 = log.hash_tile(0, 0)
    assert len(t0) == 256 * 32
    assert t0[:32] == merkle.leaf_hash(b"entry 0")
    # Level-1 tile entry 0 is the root of the first 256 leaves.
    assert log.hash_tile(1, 0, width=2)[:32] == log.root(256)
    assert log.hash_tile(0, 2, width=3)[32:64] == merkle.leaf_hash(b"entry 513")
    bundle = log.entry_bundle(2, width=3)
    assert bundle[:2] == len(b"entry 512").to_bytes(2, "big")
    assert tile_index_path(1234067) == "x001/x234/067"
    assert tile_index_path(5) == "005"
    assert tile_path(0, 1234067, 3) == "tile/0/x001/x234/067.p/3"
    assert tile_path("entries", 0) == "tile/entries/000"


def test_checkpoint_sign_and_open(log):
    for d in entries(3):
        log.append(d)
    signer = NoteSigner(ORIGIN, SigningKey.generate())
    cp = Checkpoint(ORIGIN, 3, log.root())
    note = sign_checkpoint(cp, signer)
    vc = open_checkpoint(note, [signer.verifier])
    assert vc.checkpoint == cp
    assert Checkpoint.parse_text(cp.text()) == cp
    other = NoteSigner(ORIGIN, SigningKey.generate())
    with pytest.raises(NoteError):
        open_checkpoint(note, [other.verifier])
    wrong_origin = NoteSigner("evil.example/log", signer.key)
    with pytest.raises(NoteError):
        open_checkpoint(sign_checkpoint(cp, wrong_origin), [wrong_origin.verifier])
    tampered = note.replace("\n3\n", "\n4\n", 1)
    with pytest.raises(NoteError):
        open_checkpoint(tampered, [signer.verifier])


def make_witness(tmp_path, log_signer, t=1_760_000_000):
    wsigner = NoteSigner("witness.example", SigningKey.generate(), alg=ALG_COSIGNATURE_V1)
    return Witness(wsigner, tmp_path / "w.sqlite", [log_signer.verifier], clock=lambda: t)


def test_witness_cosigns_consistent_growth(tmp_path, log):
    signer = NoteSigner(ORIGIN, SigningKey.generate())
    w = make_witness(tmp_path, signer)
    for d in entries(4):
        log.append(d)
    note4 = sign_checkpoint(Checkpoint(ORIGIN, 4, log.root()), signer)
    line = w.cosign(note4, 0, [])
    cosigned = add_signature_lines(note4, [line])
    assert verify_cosignature(parse_note(cosigned), w.verifier) == 1_760_000_000
    vc = open_checkpoint(cosigned, [signer.verifier], [w.verifier])
    assert vc.cosignatures[0][1] == 1_760_000_000

    for d in entries(9)[4:]:
        log.append(d)
    note9 = sign_checkpoint(Checkpoint(ORIGIN, 9, log.root()), signer)
    with pytest.raises(WitnessConflict) as exc:
        w.cosign(note9, 0, [])
    assert exc.value.known_size == 4
    w.cosign(note9, 4, log.consistency_proof(4, 9))
    assert w.known(ORIGIN)[0] == 9
    # Same checkpoint again is fine; an older one is refused.
    w.cosign(note9, 9, [])
    with pytest.raises(WitnessRefused):
        w.cosign(note4, 9, [])


def test_witness_refuses_fork(tmp_path):
    signer = NoteSigner(ORIGIN, SigningKey.generate())
    w = make_witness(tmp_path, signer)
    honest = SQLiteLog(tmp_path / "honest.sqlite")
    forked = SQLiteLog(tmp_path / "forked.sqlite")
    for d in entries(5):
        honest.append(d)
    w.cosign(sign_checkpoint(Checkpoint(ORIGIN, 5, honest.root()), signer), 0, [])

    # The operator shows a different history to someone else: entry 2 replaced.
    data = entries(6)
    data[2] = b"backdated entry"
    for d in data:
        forked.append(d)
    fork_note = sign_checkpoint(Checkpoint(ORIGIN, 6, forked.root()), signer)
    with pytest.raises(ForkDetected):
        w.cosign(fork_note, 5, forked.consistency_proof(5, 6))
    same_size_fork = SQLiteLog(tmp_path / "f2.sqlite")
    for d in data[:5]:
        same_size_fork.append(d)
    with pytest.raises(ForkDetected):
        w.cosign(sign_checkpoint(Checkpoint(ORIGIN, 5, same_size_fork.root()), signer), 5, [])
    # A checkpoint from an unknown log key is refused.
    other = NoteSigner(ORIGIN, SigningKey.generate())
    with pytest.raises(NoteError):
        w.cosign(sign_checkpoint(Checkpoint(ORIGIN, 6, honest.root()), other), 5, [])
    assert w.known(ORIGIN) == (5, honest.root())


def test_checkpoint_rejects_non_canonical_base64():
    import base64

    root = b"\x00" * 32
    good = base64.b64encode(root).decode("ascii")
    assert good.endswith("A=")
    # Flip the unused trailing padding bit (A -> B decodes to the same 32 zero bytes).
    malleated = good[:-2] + "B="
    assert base64.b64decode(malleated, validate=True) == root
    with pytest.raises(NoteError):
        Checkpoint.parse_text(f"{ORIGIN}\n1\n{malleated}\n")


def test_log_proof_from_json_rejects_bad_inclusion_hashes():
    from anagram.core.errors import FormatError
    from anagram.proofs.bundle import LogProof

    base = {
        "checkpoint": "example/log\n1\n" + "A" * 43 + "=\n",
        "entry": {"commitment": "00" * 32, "kind": "finding", "schema": "anagram.log_entry.v1"},
        "inclusion": ["00" * 64],  # 64 bytes instead of 32
        "leaf_index": 0,
        "tree_size": 1,
    }
    with pytest.raises(FormatError):
        LogProof.from_json(base)
    with pytest.raises(FormatError):
        LogProof.from_json({**base, "inclusion": ["AA" * 32]})
    with pytest.raises(FormatError):
        LogProof.from_json({**base, "inclusion": [], "leaf_index": True})


def test_witness_rejects_non_empty_proof_from_zero(tmp_path):
    signer = NoteSigner(ORIGIN, SigningKey.generate())
    w = make_witness(tmp_path, signer)
    log = SQLiteLog(tmp_path / "log.sqlite")
    log.append(b"first")
    note = sign_checkpoint(Checkpoint(ORIGIN, 1, log.root()), signer)
    with pytest.raises(ForkDetected):
        w.cosign(note, 0, [b"\x01" * 32])
