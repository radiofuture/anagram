"""Test vectors for the vault formats (spec/vault.md). Fixed inputs only.

`anagram.vectors.build` writes them to spec/vectors/vault.json.

HPKE output is random (a new ephemeral key each time), so the vectors give the
HPKE `info` values, not ciphertext. Shamir shares are random too; the vector
shares come from a fixed byte source and only check `combine`.
"""

from __future__ import annotations

import hashlib
from contextlib import contextmanager
from datetime import UTC, datetime

from anagram.core.canonical import canonical_json
from anagram.core.crypto import shamir
from anagram.core.crypto.blob import BLOB_ALG, blob_key, chunk_aad, chunk_nonce, encrypt_bytes
from anagram.core.crypto.signing import SigningKey
from anagram.identity.api import recovery_request_id
from anagram.identity.formats.backup import backup_id
from anagram.identity.formats.documents import device_json
from anagram.identity.formats.recovery import guardian_info, make_share, recovery_info
from anagram.network.formats.vault import (
    grant_info,
    make_grant_receipt,
    receipt_commitment,
    receipt_log_entry,
)

T0 = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
VECTOR_SUBJECT = "pid:" + "5e" * 16  # a person ID (spec/identity.md section 2)


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram vault vector seed: {label}".encode()).digest()


@contextmanager
def _fixed_rng(label: str):
    """Make pycryptodome's Shamir split use a fixed byte source (vectors only)."""
    import Crypto.Protocol.SecretSharing as ss

    counter = [0]

    def rng(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += _seed(f"{label}/{counter[0]}")
            counter[0] += 1
        return out[:n]

    old = ss.rng
    ss.rng = rng
    try:
        yield
    finally:
        ss.rng = old


def build() -> dict:
    key = _seed("content key")
    root = _seed("finding root")
    ev = _seed("evidence root")
    slot, chunk = 1, 16
    plain = b"Anagram blob vector: three chunks."  # 34 bytes: 16 + 16 + 2
    ct = encrypt_bytes(
        plain, content_key=key, finding_root=root, evidence_root=ev, slot=slot, chunk_size=chunk
    )
    n_chunks = 3
    owner = SigningKey.from_seed(_seed("owner"))
    grant_id = _seed("grant id")[:16]
    receipt = make_grant_receipt(
        finding_root=root,
        grant_id=grant_id,
        recipient=VECTOR_SUBJECT,
        granted_at=T0,
        salt=_seed("receipt salt"),
        key=owner,
    )
    device = device_json(_seed("device ed25519"), _seed("device x25519"))
    secret = _seed("guardian secret")
    with _fixed_rng("shamir"):
        shares = shamir.split(secret, 2, 3)
    set_id = _seed("set id")[:16]
    share_doc = make_share(
        owner=VECTOR_SUBJECT,
        set_id=set_id,
        index=1,
        threshold=2,
        backup_id=backup_id(secret),
        share=shares[0][1],
    )
    request = {
        "assertion": {"note": "a node assertion (identity.md section 6) goes here"},
        "created_at": "2026-10-15T12:00:00Z",
        "device": device,
        "pop": "00" * 64,
        "schema": "anagram.recovery_request.v1",
        "subject": VECTOR_SUBJECT,
    }
    rid = recovery_request_id(request)
    return {
        "description": "Vault formats: chunked blob AEAD, grant receipt, HPKE info values, "
        "guardian shares (Shamir combine), recovery request ID. Fixed seeds.",
        "blob": {
            "alg": BLOB_ALG,
            "content_key": key.hex(),
            "finding_root": root.hex(),
            "evidence_root": ev.hex(),
            "slot": slot,
            "chunk_size": chunk,
            "plaintext_hex": plain.hex(),
            "blob_key": blob_key(key, root, slot).hex(),
            "chunks": [
                {
                    "aad": chunk_aad(root, ev, slot, i, i == n_chunks - 1).hex(),
                    "index": i,
                    "nonce": chunk_nonce(i).hex(),
                }
                for i in range(n_chunks)
            ],
            "ciphertext_hex": ct.hex(),
        },
        "grant_receipt": {
            "owner_seed": _seed("owner").hex(),
            "receipt": receipt,
            "commitment": receipt_commitment(receipt).hex(),
            "log_entry": receipt_log_entry(receipt),
            "log_entry_canonical": canonical_json(receipt_log_entry(receipt)).decode(),
        },
        "hpke_info": {
            "grant": {
                "grant_id": grant_id.hex(),
                "device": device["ed25519"],
                "info_hex": grant_info(grant_id, bytes.fromhex(device["ed25519"])).hex(),
            },
            "guardian_share": {
                "set_id": set_id.hex(),
                "index": 1,
                "device": device["ed25519"],
                "info_hex": guardian_info(set_id, 1, bytes.fromhex(device["ed25519"])).hex(),
            },
            "recovery_share": {
                "request_id": rid,
                "index": 1,
                "info_hex": recovery_info(bytes.fromhex(rid), 1).hex(),
            },
        },
        "guardians": {
            "secret": secret.hex(),
            "threshold": 2,
            "shares": [{"index": i, "share": s.hex()} for i, s in shares],
            "backup_id": backup_id(secret),
            "share_document": share_doc,
        },
        "recovery_request": {"request": request, "request_id": rid},
    }
