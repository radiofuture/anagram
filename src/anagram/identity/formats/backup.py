"""Recovery secret and encrypted key backup (`anagram.key_backup.v2`).

The recovery secret is 20 random bytes (160 bits). The kit shows it as
base32 in 8 groups of 4 characters. Two values come from it with HKDF-SHA256
(RFC 5869, no salt):

    backup_key = HKDF(secret, info="anagram/v1/recovery/key", 32 bytes)
    backup_id  = HKDF(secret, info="anagram/v1/recovery/id",  32 bytes)

The node stores the backup under `backup_id`. It never sees the secret or
`backup_key`. The secret has 160 bits of entropy, so a slow KDF is not
necessary. The backup is ChaCha20-Poly1305 over the canonical JSON payload.

Version 2 adds `index-key` (the key of the local index). A client writes v2 and
still reads v1 (then `index-key` is not in the result).
"""

from __future__ import annotations

import base64
import binascii
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from anagram.core.canonical import CanonicalError, canonical_json, loads
from anagram.core.crypto import aead
from anagram.core.errors import FormatError
from anagram.identity.formats.documents import (
    KEY_BACKUP_PAYLOAD_SCHEMA,
    KEY_BACKUP_PAYLOAD_SCHEMA_V1,
    KEY_BACKUP_SCHEMA,
    KEY_BACKUP_SCHEMA_V1,
    validate_subject,
)

SECRET_LEN = 20
INFO_KEY = b"anagram/v1/recovery/key"
INFO_ID = b"anagram/v1/recovery/id"
KDF = "hkdf-sha256"
BACKUP_KEYS = ("device-ed25519", "device-x25519", "index-key", "vault-key")
BACKUP_KEYS_V1 = ("device-ed25519", "device-x25519", "vault-key")
# schema -> (payload schema, key names)
_VERSIONS = {
    KEY_BACKUP_SCHEMA: (KEY_BACKUP_PAYLOAD_SCHEMA, BACKUP_KEYS),
    KEY_BACKUP_SCHEMA_V1: (KEY_BACKUP_PAYLOAD_SCHEMA_V1, BACKUP_KEYS_V1),
}


def new_recovery_secret() -> bytes:
    return secrets.token_bytes(SECRET_LEN)


def encode_secret(secret: bytes) -> str:
    text = base64.b32encode(secret).decode("ascii")
    return "-".join(text[i : i + 4] for i in range(0, len(text), 4))


def decode_secret(text: str) -> bytes:
    clean = "".join(c for c in text.upper() if c.isalnum())
    try:
        secret = base64.b32decode(clean)
    except (binascii.Error, ValueError) as exc:
        raise FormatError("recovery code is not valid base32") from exc
    if len(secret) != SECRET_LEN:
        raise FormatError("recovery code has the wrong length")
    return secret


def _hkdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def backup_id(secret: bytes) -> str:
    return _hkdf(secret, INFO_ID).hex()


def backup_key(secret: bytes) -> bytes:
    return _hkdf(secret, INFO_KEY)


def _aad(doc: dict) -> bytes:
    return canonical_json({k: v for k, v in doc.items() if k not in ("ciphertext", "nonce")})


def seal_backup(
    secret: bytes,
    subject: str,
    keys: dict[str, bytes],
    nonce: bytes | None = None,
    *,
    schema: str = KEY_BACKUP_SCHEMA,
) -> dict:
    """Seal a key backup. `schema` v1 is only for tests of the old version."""
    validate_subject(subject)
    payload_schema, names = _VERSIONS[schema]
    if set(keys) != set(names):
        raise FormatError("backup needs exactly: " + ", ".join(names))
    payload = {
        "keys": {k: v.hex() for k, v in sorted(keys.items())},
        "schema": payload_schema,
        "subject": subject,
    }
    doc = {
        "alg": aead.AEAD_ALG,
        "backup_id": backup_id(secret),
        "kdf": KDF,
        "schema": schema,
        "subject": subject,
    }
    n, ct = aead.seal(backup_key(secret), canonical_json(payload), _aad(doc), nonce)
    doc["ciphertext"] = base64.b64encode(ct).decode("ascii")
    doc["nonce"] = n.hex()
    return doc


def validate_backup(doc: Any) -> dict:
    names = {"alg", "backup_id", "ciphertext", "kdf", "nonce", "schema", "subject"}
    if not isinstance(doc, dict) or set(doc) != names:
        raise FormatError("key backup: fields do not match the schema")
    if doc["schema"] not in _VERSIONS or doc["alg"] != aead.AEAD_ALG or doc["kdf"] != KDF:
        raise FormatError("key backup: unknown schema or algorithm")
    validate_subject(doc["subject"])
    try:
        if len(bytes.fromhex(doc["backup_id"])) != 32 or len(bytes.fromhex(doc["nonce"])) != 12:
            raise ValueError("sizes")
        base64.b64decode(doc["ciphertext"], validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise FormatError("key backup: bad encoding") from exc
    return doc


def open_backup(secret: bytes, doc: dict) -> dict[str, bytes]:
    validate_backup(doc)
    if doc["backup_id"] != backup_id(secret):
        raise FormatError("this recovery code is not for this backup")
    try:
        plain = aead.open_sealed(
            backup_key(secret),
            bytes.fromhex(doc["nonce"]),
            base64.b64decode(doc["ciphertext"]),
            _aad(doc),
        )
        payload = loads(plain)
    except (InvalidTag, CanonicalError, ValueError) as exc:
        raise FormatError("key backup does not open with this recovery code") from exc
    payload_schema, names = _VERSIONS[doc["schema"]]
    if payload.get("schema") != payload_schema or payload.get("subject") != doc["subject"]:
        raise FormatError("key backup payload does not match")
    keys = payload["keys"]
    if set(keys) != set(names):
        raise FormatError("key backup payload has the wrong keys")
    return {k: bytes.fromhex(v) for k, v in keys.items()}
