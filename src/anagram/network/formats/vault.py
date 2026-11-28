"""Vault formats: grant receipt, grant, grant payload, public release.
See spec/vault.md. The guardian and recovery formats are in `recovery.py`
(L1), and the key wraps in `anagram.core.wraps`.

The node sees only: grant envelopes (recipient subject, device keys, blob IDs,
HPKE ciphertext), public releases (public by intent), and grant receipt
commitments in the log (a hash).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.blob import BLOB_ALG
from anagram.core.crypto.hashing import (
    TAG_GRANT_RECEIPT,
    TAG_HPKE_GRANT,
    TAG_SIGN_GRANT_RECEIPT,
    tagged_hash,
    tagged_message,
)
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, exact_fields, hex_field, int_in
from anagram.core.wraps import validate_wraps
from anagram.identity.api import validate_subject
from anagram.proofs.records import KIND_GRANT_RECEIPT, LOG_ENTRY_SCHEMA

GRANT_RECEIPT_SCHEMA = "anagram.grant_receipt.v1"
GRANT_SCHEMA = "anagram.grant.v1"
GRANT_PAYLOAD_SCHEMA = "anagram.grant_payload.v1"
PUBLIC_RELEASE_SCHEMA = "anagram.public_release.v1"

PUBLIC = "public"
MAX_BLOBS = 4096


def _recipient(value: Any) -> str:
    if value == PUBLIC:
        return PUBLIC
    return validate_subject(value)


# ------------------------------------------------------------- grant receipt


def make_grant_receipt(
    *,
    finding_root: bytes,
    grant_id: bytes,
    recipient: str,
    granted_at: datetime,
    salt: bytes,
    key: SigningKey,
) -> JsonObject:
    """The owner's signed statement "I gave finding R to recipient X at time T".
    Only its commitment goes into the log. The salt hides it."""
    doc = {
        "finding_root": finding_root.hex(),
        "grant_id": grant_id.hex(),
        "granted_at": format_time(granted_at),
        "recipient": _recipient(recipient),
        "salt": salt.hex(),
        "schema": GRANT_RECEIPT_SCHEMA,
        "sender_key": key.public_bytes().hex(),
    }
    doc["signature"] = key.sign(TAG_SIGN_GRANT_RECEIPT, canonical_json(doc)).hex()
    return validate_grant_receipt(doc)


def validate_grant_receipt(doc: Any) -> JsonObject:
    names = {
        "finding_root",
        "grant_id",
        "granted_at",
        "recipient",
        "salt",
        "schema",
        "sender_key",
        "signature",
    }
    checked = exact_fields(doc, names, "grant receipt")
    if doc["schema"] != GRANT_RECEIPT_SCHEMA:
        raise FormatError("grant receipt: unknown schema")
    hex_field(doc["finding_root"], HEX32, "finding_root")
    hex_field(doc["grant_id"], HEX16, "grant_id")
    hex_field(doc["salt"], HEX32, "salt")
    hex_field(doc["sender_key"], HEX32, "sender_key")
    hex_field(doc["signature"], HEX64, "signature")
    _recipient(doc["recipient"])
    parse_time(doc["granted_at"])
    return checked


def verify_grant_receipt(doc: Any) -> JsonObject:
    checked = validate_grant_receipt(doc)
    if not doc_signature_ok(doc, TAG_SIGN_GRANT_RECEIPT, bytes.fromhex(doc["sender_key"])):
        raise FormatError("grant receipt: bad signature")
    return checked


def receipt_commitment(doc: JsonObject) -> bytes:
    return tagged_hash(TAG_GRANT_RECEIPT, canonical_json(doc))


def receipt_log_entry(doc: JsonObject) -> JsonObject:
    return {
        "commitment": receipt_commitment(doc).hex(),
        "kind": KIND_GRANT_RECEIPT,
        "schema": LOG_ENTRY_SCHEMA,
    }


# ---------------------------------------------------------- grant and payload


def grant_info(grant_id: bytes, device_ed25519: bytes) -> bytes:
    return tagged_message(TAG_HPKE_GRANT, grant_id + device_ed25519)


def _validate_blob_list(blobs: Any) -> list[JsonObject]:
    if not isinstance(blobs, list) or len(blobs) > MAX_BLOBS:
        raise FormatError("blobs: bad list")
    slots = []
    for b in blobs:
        exact_fields(b, {"blob_id", "chunk_size", "size", "slot"}, "blob")
        hex_field(b["blob_id"], HEX16, "blob_id")
        int_in(b["chunk_size"], 1, 1 << 26, "chunk_size")
        int_in(b["size"], 0, (1 << 63) - 1, "size")
        slots.append(int_in(b["slot"], 0, (1 << 16) - 1, "slot"))
    if slots != sorted(set(slots)):
        raise FormatError("blobs: slots must be sorted and unique")
    return blobs


def make_payload(
    *,
    schema: str,
    owner: str,
    recipient: str,
    finding_id: str,
    version: int,
    content_key: bytes,
    opening: JsonObject,
    bundle: JsonObject,
    blobs: list[JsonObject],
    receipt: JsonObject,
    receipt_log: JsonObject,
) -> JsonObject:
    doc = {
        "blob_alg": BLOB_ALG,
        "blobs": sorted(blobs, key=lambda b: b["slot"]),
        "bundle": bundle,
        "content_key": content_key.hex(),
        "finding_id": finding_id,
        "opening": opening,
        "owner": owner,
        "receipt": receipt,
        "receipt_log": receipt_log,
        "recipient": recipient,
        "schema": schema,
        "version": version,
    }
    return validate_payload(doc, schema)


def validate_payload(doc: Any, schema: str = GRANT_PAYLOAD_SCHEMA) -> JsonObject:
    names = {
        "blob_alg",
        "blobs",
        "bundle",
        "content_key",
        "finding_id",
        "opening",
        "owner",
        "receipt",
        "receipt_log",
        "recipient",
        "schema",
        "version",
    }
    checked = exact_fields(doc, names, "grant payload")
    if doc["schema"] != schema or schema not in (GRANT_PAYLOAD_SCHEMA, PUBLIC_RELEASE_SCHEMA):
        raise FormatError("grant payload: unknown schema")
    if doc["blob_alg"] != BLOB_ALG:
        raise FormatError("grant payload: unknown blob algorithm")
    _validate_blob_list(doc["blobs"])
    hex_field(doc["content_key"], HEX32, "content_key")
    hex_field(doc["finding_id"], HEX16, "finding_id")
    int_in(doc["version"], 1, 2**53 - 1, "version")
    validate_subject(doc["owner"])
    _recipient(doc["recipient"])
    if (schema == PUBLIC_RELEASE_SCHEMA) != (doc["recipient"] == PUBLIC):
        raise FormatError("grant payload: a public release is for 'public' only")
    validate_grant_receipt(doc["receipt"])
    if doc["receipt"]["recipient"] != doc["recipient"]:
        raise FormatError("grant payload: receipt is for another recipient")
    for name in ("opening", "bundle", "receipt_log"):
        if not isinstance(doc[name], dict):
            raise FormatError(f"grant payload: bad {name}")
    return checked


def validate_grant(doc: Any) -> JsonObject:
    """The envelope that the node stores and routes."""
    checked = exact_fields(doc, {"blobs", "grant_id", "recipient", "schema", "wraps"}, "grant")
    if doc["schema"] != GRANT_SCHEMA:
        raise FormatError("grant: unknown schema")
    hex_field(doc["grant_id"], HEX16, "grant_id")
    validate_subject(doc["recipient"])
    if not isinstance(doc["blobs"], list) or len(doc["blobs"]) > MAX_BLOBS:
        raise FormatError("grant: bad blob list")
    for b in doc["blobs"]:
        hex_field(b, HEX16, "blob id")
    validate_wraps(doc["wraps"])
    return checked


def validate_public_release(doc: Any) -> JsonObject:
    return validate_payload(doc, PUBLIC_RELEASE_SCHEMA)


__all__ = [
    "PUBLIC",
    "grant_info",
    "make_grant_receipt",
    "make_payload",
    "receipt_commitment",
    "receipt_log_entry",
    "validate_grant",
    "validate_grant_receipt",
    "validate_payload",
    "validate_public_release",
    "verify_grant_receipt",
]
