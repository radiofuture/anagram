"""Test vectors for the sharing formats (spec/vault.md sections 12 to 14).
Fixed inputs only. `anagram.vectors.build` writes them to
spec/vectors/sharing.json.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from anagram.core.canonical import canonical_json
from anagram.core.crypto.blob import encrypt_bytes
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats.sharing import (
    READING_COPY_SCHEMA,
    READING_SLOT,
    make_fetch_event,
    make_read_receipt,
    read_receipt_commitment,
    read_receipt_id,
    read_receipt_log_entry,
    reading_blob_id,
    reading_evidence_root,
    reading_key,
    validate_reading_copy,
)

T0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)
READER = "pid:" + "7a" * 16
NODE_KEY = "3c" * 32


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram sharing vector seed: {label}".encode()).digest()


def build() -> dict:
    reader = SigningKey.from_seed(_seed("reader device"))
    host = SigningKey.from_seed(_seed("host assertion"))
    grant_id = _seed("grant id")[:16]
    receipt = make_read_receipt(
        grant_id=grant_id, reader=READER, read_at=T0, salt=_seed("receipt salt"), key=reader
    )
    rid = read_receipt_id(receipt)
    events = [
        make_fetch_event(
            at=T0,
            grant_id=grant_id.hex(),
            blob_id=blob,
            reader=READER,
            receipt_id=rid,
            seq=seq,
            node_key=NODE_KEY,
            key=host,
        )
        for seq, blob in ((1, None), (2, _seed("blob id")[:16].hex()))
    ]
    content_key = _seed("content key")
    root = _seed("finding root")
    copy = validate_reading_copy(
        {
            "items": [
                {
                    "blocks": [
                        {
                            "anchor": "heading-1",
                            "kind": "heading",
                            "level": 1,
                            "parent": None,
                            "text": "Result",
                        },
                        {
                            "anchor": "para-1",
                            "kind": "para",
                            "level": 0,
                            "parent": None,
                            "text": "Cells grow faster at 30 C.",
                        },
                    ],
                    "figures": [],
                    "media_type": "text/markdown",
                    "name": "result.md",
                    "size": 36,
                    "slot": 0,
                    "table": None,
                    "truncated": False,
                    "view": "text",
                }
            ],
            "made_by": "anagram.readcopy.v1",
            "schema": READING_COPY_SCHEMA,
            "title": "Result",
        }
    )
    plain = canonical_json(copy)
    rkey = reading_key(content_key, root)
    ct = encrypt_bytes(
        plain,
        content_key=rkey,
        finding_root=root,
        evidence_root=reading_evidence_root(),
        slot=READING_SLOT,
        chunk_size=1 << 20,
    )
    return {
        "description": "Sharing formats: read receipt (commitment, receipt ID, log entry),"
        " host fetch events, reading copy key, blob ID, and blob. Fixed seeds.",
        "read_receipt": {
            "reader_seed": _seed("reader device").hex(),
            "receipt": receipt,
            "commitment": read_receipt_commitment(receipt).hex(),
            "receipt_id": rid,
            "log_entry": read_receipt_log_entry(receipt),
            "log_entry_canonical": canonical_json(read_receipt_log_entry(receipt)).decode(),
        },
        "fetch_events": {
            "assertion_key": host.public_bytes().hex(),
            "node_key": NODE_KEY,
            "events": events,
        },
        "reading_copy": {
            "content_key": content_key.hex(),
            "finding_root": root.hex(),
            "reading_key": rkey.hex(),
            "blob_id": reading_blob_id(content_key, root),
            "evidence_root": reading_evidence_root().hex(),
            "slot": READING_SLOT,
            "chunk_size": 1 << 20,
            "document": copy,
            "ciphertext_hex": ct.hex(),
        },
    }
