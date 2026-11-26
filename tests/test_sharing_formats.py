"""R5 step 1: read receipt, fetch event, reading copy formats and the
`read_receipt` log kind."""

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from anagram.core.canonical import canonical_json
from anagram.core.crypto.blob import decrypt_bytes
from anagram.core.crypto.hashing import ALL_TAGS
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.network.formats.sharing import (
    make_fetch_event,
    make_read_receipt,
    read_receipt_commitment,
    read_receipt_id,
    read_receipt_log_entry,
    reading_blob_id,
    reading_evidence_root,
    reading_key,
    seq_gaps,
    validate_reading_copy,
    verify_fetch_event,
    verify_read_receipt,
)
from anagram.proofs.node.service import validate_entry
from anagram.proofs.records import KIND_READ_RECEIPT, LOG_ONLY_KINDS

V = json.loads((Path(__file__).parent.parent / "spec/vectors/sharing.json").read_text())
T = datetime(2026, 11, 16, 9, 30, tzinfo=UTC)
READER = "pid:" + "ab" * 16


def _receipt(key=None, **kw):
    args = {
        "grant_id": bytes(range(16)),
        "reader": READER,
        "read_at": T,
        "salt": bytes(32),
        "key": key or SigningKey.generate(),
    }
    args.update(kw)
    return make_read_receipt(**args)


def test_tags_are_unique():
    assert len(set(ALL_TAGS)) == len(ALL_TAGS)
    assert "anagram/v1/read-receipt" in ALL_TAGS
    # Guest tags are later work (decision P10).
    assert not any("guest" in t for t in ALL_TAGS)


def test_read_receipt_vector_verifies():
    v = V["read_receipt"]
    doc = verify_read_receipt(v["receipt"])
    key = SigningKey.from_seed(bytes.fromhex(v["reader_seed"]))
    assert doc["reader_key"] == key.public_bytes().hex()
    assert read_receipt_commitment(doc).hex() == v["commitment"]
    assert read_receipt_id(doc) == v["receipt_id"] == v["commitment"][:32]
    assert read_receipt_log_entry(doc) == v["log_entry"]
    assert canonical_json(v["log_entry"]).decode() == v["log_entry_canonical"]


def test_read_receipt_opens_and_verifies():
    key = SigningKey.generate()
    doc = _receipt(key)
    assert verify_read_receipt(doc) is doc
    entry = read_receipt_log_entry(doc)
    assert entry["kind"] == KIND_READ_RECEIPT
    # A changed field breaks the signature.
    for name, value in (("read_at", "2026-11-16T09:31:00Z"), ("grant_id", "00" * 16)):
        bad = {**doc, name: value}
        with pytest.raises(FormatError):
            verify_read_receipt(bad)
    # A signature of another key does not verify.
    other = _receipt(SigningKey.generate())
    with pytest.raises(FormatError):
        verify_read_receipt({**doc, "signature": other["signature"]})


def test_read_receipt_refuses_unknown_and_bad_fields():
    doc = _receipt()
    with pytest.raises(FormatError):
        verify_read_receipt({**doc, "finding_root": "00" * 32})
    with pytest.raises(FormatError):
        verify_read_receipt({**doc, "reader": "someone"})
    with pytest.raises(FormatError):
        _receipt(grant_id=b"short")
    with pytest.raises(FormatError):
        _receipt(salt=b"\0" * 16)


def test_read_commitment_hides_reader():
    """Two receipts with the same reader, grant, and time but other salts have
    unrelated commitments, and no commitment holds the pid or the grant."""
    key = SigningKey.generate()
    a = _receipt(key, salt=bytes(32))
    b = _receipt(key, salt=b"\1" * 32)
    ca, cb = read_receipt_commitment(a), read_receipt_commitment(b)
    assert ca != cb
    entry = canonical_json(read_receipt_log_entry(a))
    assert READER.encode() not in entry and a["grant_id"].encode() not in entry


def test_log_accepts_read_receipt_kind():
    assert KIND_READ_RECEIPT in LOG_ONLY_KINDS
    entry = read_receipt_log_entry(_receipt())
    assert validate_entry(entry) == canonical_json(entry)


def test_fetch_event_vector_verifies():
    v = V["fetch_events"]
    key = bytes.fromhex(v["assertion_key"])
    for ev in v["events"]:
        verify_fetch_event(ev, key, v["node_key"])
    assert [e["seq"] for e in v["events"]] == [1, 2]
    assert v["events"][0]["blob_id"] is None


def test_fetch_event_checks():
    node_signer = SigningKey.generate()
    node_key = "11" * 32
    ev = make_fetch_event(
        at=T,
        grant_id="22" * 16,
        blob_id=None,
        reader=READER,
        receipt_id="33" * 16,
        seq=1,
        node_key=node_key,
        key=node_signer,
    )
    verify_fetch_event(ev, node_signer.public_bytes(), node_key)
    with pytest.raises(FormatError):
        verify_fetch_event(ev, SigningKey.generate().public_bytes(), node_key)
    with pytest.raises(FormatError):
        verify_fetch_event(ev, node_signer.public_bytes(), "44" * 32)
    with pytest.raises(FormatError):
        verify_fetch_event({**ev, "seq": 2}, node_signer.public_bytes(), node_key)
    with pytest.raises(FormatError):
        make_fetch_event(**{**_event_args(node_signer, node_key), "seq": 0})


def _event_args(node_signer, node_key):
    return {
        "at": T,
        "grant_id": "22" * 16,
        "blob_id": "55" * 16,
        "reader": READER,
        "receipt_id": "33" * 16,
        "seq": 1,
        "node_key": node_key,
        "key": node_signer,
    }


def test_seq_gaps():
    assert seq_gaps([]) == []
    assert seq_gaps([1, 2, 3]) == []
    assert seq_gaps([1, 4, 2]) == [3]
    assert seq_gaps([3]) == [1, 2]


def test_reading_copy_vector_decrypts():
    v = V["reading_copy"]
    ck, root = bytes.fromhex(v["content_key"]), bytes.fromhex(v["finding_root"])
    assert reading_key(ck, root).hex() == v["reading_key"]
    assert reading_blob_id(ck, root) == v["blob_id"]
    assert reading_evidence_root().hex() == v["evidence_root"]
    plain = decrypt_bytes(
        bytes.fromhex(v["ciphertext_hex"]),
        content_key=bytes.fromhex(v["reading_key"]),
        finding_root=root,
        evidence_root=reading_evidence_root(),
        slot=v["slot"],
        chunk_size=v["chunk_size"],
    )
    assert plain == canonical_json(v["document"])
    validate_reading_copy(json.loads(plain))


def test_reading_keys_depend_on_content_key_and_root():
    ck, root = b"\1" * 32, b"\2" * 32
    assert reading_key(ck, root) != reading_key(b"\3" * 32, root)
    assert reading_key(ck, root) != reading_key(ck, b"\4" * 32)
    assert reading_key(ck, root) != ck
    assert reading_blob_id(ck, root) != reading_blob_id(ck, b"\4" * 32)
    assert len(reading_blob_id(ck, root)) == 32


def test_reading_copy_refusals():
    good = V["reading_copy"]["document"]
    validate_reading_copy(copy.deepcopy(good))
    cases = []
    d = copy.deepcopy(good)
    d["extra"] = 1
    cases.append(d)
    d = copy.deepcopy(good)
    d["items"][0]["view"] = "html"
    cases.append(d)
    d = copy.deepcopy(good)
    d["items"].append(copy.deepcopy(d["items"][0]))  # repeated slot
    cases.append(d)
    d = copy.deepcopy(good)
    d["items"][0]["figures"] = [{"data": "AAAA", "id": "f1", "media_type": "text/html"}]
    cases.append(d)
    d = copy.deepcopy(good)
    d["items"][0]["table"] = {"columns": ["a"], "rows": [["1"]] * 501, "total_rows": 501}
    cases.append(d)
    d = copy.deepcopy(good)
    d["items"][0]["truncated"] = 0
    cases.append(d)
    for bad in cases:
        with pytest.raises(FormatError):
            validate_reading_copy(bad)


def test_reading_copy_size_limit():
    doc = copy.deepcopy(V["reading_copy"]["document"])
    doc["items"][0]["blocks"][1]["text"] = "x" * (8 << 20)
    with pytest.raises(FormatError):
        validate_reading_copy(doc)
