"""Sealed opening: opening data encrypted at rest with the owner's vault key.

Format `anagram.sealed_opening.v1`:

    {
      "alg": "chacha20-poly1305",
      "ciphertext": <base64>,
      "key_id": <hex, 8 bytes>,
      "nonce": <hex, 12 bytes>,
      "schema": "anagram.sealed_opening.v1",
      "subject_root": <hex, 32 bytes>
    }

The plaintext is canonical JSON of an `anagram.opening.v1` document. The AAD is
canonical JSON of the envelope without `ciphertext` and `nonce`. So the
ciphertext is bound to the subject root, key ID, and algorithm.
"""

from __future__ import annotations

import base64

from anagram.core.canonical import canonical_json, loads_canonical
from anagram.core.crypto import aead
from anagram.core.crypto.hashing import TAG_VAULT_KEY_ID, tagged_hash
from anagram.core.errors import FormatError
from anagram.proofs.records import OpeningDocument

SEALED_SCHEMA = "anagram.sealed_opening.v1"


def vault_key_id(key: bytes) -> str:
    return tagged_hash(TAG_VAULT_KEY_ID, key)[:8].hex()


def _aad(header: dict) -> bytes:
    return canonical_json(header)


def seal_opening(
    vault_key: bytes, subject_root: bytes, doc: OpeningDocument, nonce: bytes | None = None
) -> dict:
    header = {
        "alg": aead.AEAD_ALG,
        "key_id": vault_key_id(vault_key),
        "schema": SEALED_SCHEMA,
        "subject_root": subject_root.hex(),
    }
    nonce, ct = aead.seal(vault_key, canonical_json(doc.to_json()), _aad(header), nonce)
    return {**header, "ciphertext": base64.b64encode(ct).decode(), "nonce": nonce.hex()}


def unseal_opening(vault_key: bytes, sealed: dict) -> OpeningDocument:
    if sealed.get("schema") != SEALED_SCHEMA or sealed.get("alg") != aead.AEAD_ALG:
        raise FormatError("unknown sealed opening format")
    if sealed.get("key_id") != vault_key_id(vault_key):
        raise FormatError("sealed opening uses a different vault key")
    header = {k: sealed[k] for k in ("alg", "key_id", "schema", "subject_root")}
    plaintext = aead.open_sealed(
        vault_key,
        bytes.fromhex(sealed["nonce"]),
        base64.b64decode(sealed["ciphertext"], validate=True),
        _aad(header),
    )
    doc = OpeningDocument.from_json(loads_canonical(plaintext))
    if doc.finding.root().hex() != sealed["subject_root"]:
        raise FormatError("opening does not match the subject root")
    return doc
