"""Personal store records (`anagram.personal_store.v1`) and person keys
(`anagram.person_keys.v1`). See spec/vault.md section 11.

The personal store keeps the data that makes the person's proofs work (sealed
openings, content keys, bundles, rings, the ORCID opening, a snapshot of the
local index) on a node, as ciphertext. Any device of the person with the vault
key can read it. The node sees only opaque record IDs, versions, sizes, and
times.

Keys (HKDF-SHA256, RFC 5869, no salt, from the person's vault key):

    store_key = HKDF(vault_key, info = tagged_message(TAG_STORE_KEY, "enc"), 32)
    id_key    = HKDF(vault_key, info = tagged_message(TAG_STORE_KEY, "id"),  32)
    key_id    = hex(tagged_hash(TAG_STORE_KEY, "key-id" || store_key)[:8])
    record_id = hex(HMAC-SHA256(id_key,
                     tagged_message(TAG_STORE_RECORD_ID, lp(kind) || ref))[:16])

Record:

    {"alg": "chacha20-poly1305", "ciphertext": <base64>, "key_id": <16 hex>,
     "nonce": <24 hex>, "record_id": <32 hex>,
     "schema": "anagram.personal_store.v1", "version": <int >= 1>}

    aad       = tagged_message(TAG_STORE_RECORD, canonical_json(record without
                ciphertext and nonce))
    plaintext = u32(len(body)) || body || zero bytes to a multiple of 512
    body      = canonical_json({"kind": kind, "ref": ref, "value": value})

The padding hides small size differences. The reader checks that the record ID
of (kind, ref) equals `record_id`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from anagram.core.canonical import CanonicalError, canonical_json, loads_canonical
from anagram.core.crypto import aead, hpke
from anagram.core.crypto.hashing import (
    TAG_HPKE_PERSON_KEYS,
    TAG_SIGN_PERSON_KEYS,
    TAG_STORE_KEY,
    TAG_STORE_RECORD,
    TAG_STORE_RECORD_ID,
    lp,
    tagged_hash,
    tagged_message,
    u32,
)
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.identity.formats.documents import validate_subject

STORE_SCHEMA = "anagram.personal_store.v1"
PERSON_KEYS_SCHEMA = "anagram.person_keys.v1"
PERSON_KEYS_PAYLOAD_SCHEMA = "anagram.person_keys_payload.v1"
PERSON_KEY_NAMES = ("index-key", "vault-key")
PAD = 512
MAX_RECORD_BYTES = 4 << 20  # ciphertext bytes in one record

_HEX8 = re.compile(r"^[0-9a-f]{16}$")
_HEX12 = re.compile(r"^[0-9a-f]{24}$")
_HEX16 = re.compile(r"^[0-9a-f]{32}$")
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_FIELDS = {"alg", "ciphertext", "key_id", "nonce", "record_id", "schema", "version"}


def _hkdf(vault_key: bytes, label: bytes) -> bytes:
    if len(vault_key) != 32:
        raise FormatError("vault key must be 32 bytes")
    info = tagged_message(TAG_STORE_KEY, label)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(vault_key)


class StoreKeys:
    """The keys of one person's store, derived from the vault key."""

    def __init__(self, vault_key: bytes) -> None:
        self.enc = _hkdf(vault_key, b"enc")
        self.ids = _hkdf(vault_key, b"id")
        self.key_id = tagged_hash(TAG_STORE_KEY, b"key-id", self.enc)[:8].hex()

    def record_id(self, kind: str, ref: str) -> str:
        msg = tagged_message(TAG_STORE_RECORD_ID, lp(kind.encode("utf-8")) + ref.encode("utf-8"))
        return hmac.new(self.ids, msg, hashlib.sha256).digest()[:16].hex()


def _aad(header: dict) -> bytes:
    return tagged_message(TAG_STORE_RECORD, canonical_json(header))


def _pad(body: bytes) -> bytes:
    raw = u32(len(body)) + body
    return raw + bytes(-len(raw) % PAD)


def _unpad(raw: bytes) -> bytes:
    if len(raw) < 4:
        raise FormatError("store record: plaintext is too short")
    n = int.from_bytes(raw[:4], "big")
    if n > len(raw) - 4 or any(raw[4 + n :]):
        raise FormatError("store record: bad padding")
    return raw[4 : 4 + n]


def seal_record(
    keys: StoreKeys,
    kind: str,
    ref: str,
    value: Any,
    version: int,
    nonce: bytes | None = None,
) -> dict:
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise FormatError("store record: version must be >= 1")
    header = {
        "alg": aead.AEAD_ALG,
        "key_id": keys.key_id,
        "record_id": keys.record_id(kind, ref),
        "schema": STORE_SCHEMA,
        "version": version,
    }
    body = canonical_json({"kind": kind, "ref": ref, "value": value})
    n, ct = aead.seal(keys.enc, _pad(body), _aad(header), nonce)
    doc = {**header, "ciphertext": base64.b64encode(ct).decode("ascii"), "nonce": n.hex()}
    if len(ct) > MAX_RECORD_BYTES:
        raise FormatError("store record is too large")
    return doc


def validate_record(doc: Any) -> dict:
    """Check the form of a record (the node does this; it has no key)."""
    if not isinstance(doc, dict) or set(doc) != _RECORD_FIELDS:
        raise FormatError("store record: fields do not match the schema")
    if doc["schema"] != STORE_SCHEMA or doc["alg"] != aead.AEAD_ALG:
        raise FormatError("store record: unknown schema or algorithm")
    v = doc["version"]
    if not isinstance(v, int) or isinstance(v, bool) or v < 1:
        raise FormatError("store record: bad version")
    for name, pattern in (("key_id", _HEX8), ("nonce", _HEX12), ("record_id", _HEX16)):
        if not isinstance(doc[name], str) or not pattern.match(doc[name]):
            raise FormatError(f"store record: bad {name}")
    try:
        ct = base64.b64decode(doc["ciphertext"], validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise FormatError("store record: bad ciphertext encoding") from exc
    if len(ct) > MAX_RECORD_BYTES:
        raise FormatError("store record is too large")
    return doc


def record_size(doc: dict) -> int:
    """Ciphertext bytes of a record (what the node counts for the quota)."""
    return len(base64.b64decode(doc["ciphertext"]))


def open_record(keys: StoreKeys, doc: dict) -> tuple[str, str, Any]:
    """Decrypt and check a record. Return (kind, ref, value)."""
    validate_record(doc)
    if doc["key_id"] != keys.key_id:
        raise FormatError("store record uses a different vault key")
    header = {k: doc[k] for k in ("alg", "key_id", "record_id", "schema", "version")}
    try:
        raw = aead.open_sealed(
            keys.enc, bytes.fromhex(doc["nonce"]), base64.b64decode(doc["ciphertext"]), _aad(header)
        )
        body = loads_canonical(_unpad(raw))
    except (InvalidTag, CanonicalError, ValueError) as exc:
        raise FormatError("store record does not decrypt (changed or wrong key)") from exc
    if not isinstance(body, dict) or set(body) != {"kind", "ref", "value"}:
        raise FormatError("store record: bad body")
    kind, ref = body["kind"], body["ref"]
    if not isinstance(kind, str) or not isinstance(ref, str):
        raise FormatError("store record: bad kind or ref")
    if keys.record_id(kind, ref) != doc["record_id"]:
        raise FormatError("store record: ID does not match its content")
    return kind, ref, body["value"]


# ---------------------------------------------------------------- person keys


def person_keys_info(subject: str, recipient: str) -> bytes:
    return tagged_message(
        TAG_HPKE_PERSON_KEYS, lp(subject.encode("utf-8")) + bytes.fromhex(recipient)
    )


def make_person_keys(
    *,
    subject: str,
    recipient: dict,
    keys: dict[str, bytes],
    created_at: datetime,
    sender: SigningKey,
) -> dict:
    """Seal the person keys (vault key, index key) to one new device of the same
    person (HPKE to its X25519 key). The sender device signs the package."""
    validate_subject(subject)
    if set(keys) != set(PERSON_KEY_NAMES):
        raise FormatError("person keys need exactly: " + ", ".join(PERSON_KEY_NAMES))
    payload = {
        "keys": {k: v.hex() for k, v in sorted(keys.items())},
        "schema": PERSON_KEYS_PAYLOAD_SCHEMA,
        "subject": subject,
    }
    sealed = hpke.seal(
        bytes.fromhex(recipient["x25519"]),
        canonical_json(payload),
        person_keys_info(subject, recipient["ed25519"]),
    )
    doc = {
        "ciphertext": base64.b64encode(sealed).decode("ascii"),
        "created_at": format_time(created_at),
        "recipient": recipient["ed25519"],
        "schema": PERSON_KEYS_SCHEMA,
        "sender": sender.public_bytes().hex(),
        "subject": subject,
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_PERSON_KEYS, sender)
    return validate_person_keys(doc)


def validate_person_keys(doc: Any) -> dict:
    names = {"ciphertext", "created_at", "recipient", "schema", "sender", "signature", "subject"}
    if not isinstance(doc, dict) or set(doc) != names:
        raise FormatError("person keys: fields do not match the schema")
    if doc["schema"] != PERSON_KEYS_SCHEMA:
        raise FormatError("person keys: unknown schema")
    validate_subject(doc["subject"])
    for name in ("recipient", "sender"):
        if not isinstance(doc[name], str) or not _HEX32.match(doc[name]):
            raise FormatError(f"person keys: bad {name}")
    parse_time(doc["created_at"])
    try:
        base64.b64decode(doc["ciphertext"], validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise FormatError("person keys: bad ciphertext encoding") from exc
    return doc


def open_person_keys(doc: dict, private_x25519, me: str, subject: str) -> dict[str, bytes]:
    """Check the signature of the sender key (the caller checks that the sender
    is an active device of `subject`), then decrypt."""
    validate_person_keys(doc)
    if doc["recipient"] != me or doc["subject"] != subject:
        raise FormatError("person keys are for another device or person")
    if not doc_signature_ok(doc, TAG_SIGN_PERSON_KEYS, bytes.fromhex(doc["sender"])):
        raise FormatError("person keys have a bad signature")
    try:
        plain = hpke.open_sealed(
            private_x25519, base64.b64decode(doc["ciphertext"]), person_keys_info(subject, me)
        )
        payload = loads_canonical(plain)
    except (InvalidTag, CanonicalError, ValueError) as exc:
        raise FormatError("person keys do not decrypt") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != PERSON_KEYS_PAYLOAD_SCHEMA
        or payload.get("subject") != subject
        or set(payload.get("keys") or {}) != set(PERSON_KEY_NAMES)
    ):
        raise FormatError("person keys payload does not match")
    out = {k: bytes.fromhex(v) for k, v in payload["keys"].items()}
    if any(len(v) != 32 for v in out.values()):
        raise FormatError("person keys must be 32 bytes")
    return out
