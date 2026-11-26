"""Recovery formats (L1 identity): guardian set and share, recovery request
and guardian approval. See spec/vault.md, sections on guardians and recovery.

The node sees guardian sets (guardian subjects and HPKE ciphertext) and
recovery requests (public keys and a node assertion).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from anagram.core.canonical import canonical_json
from anagram.core.crypto.hashing import (
    TAG_HPKE_GUARDIAN,
    TAG_HPKE_RECOVERY,
    TAG_RECOVERY_REQUEST_ID,
    tagged_hash,
    tagged_message,
)
from anagram.core.errors import FormatError
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, exact_fields, hex_field, int_in
from anagram.core.wraps import b64_field, validate_wraps
from anagram.identity.formats.documents import validate_subject

GUARDIAN_SET_SCHEMA = "anagram.guardian_set.v1"
GUARDIAN_SHARE_SCHEMA = "anagram.guardian_share.v1"
RECOVERY_REQUEST_SCHEMA = "anagram.recovery_request.v1"
GUARDIAN_APPROVAL_SCHEMA = "anagram.guardian_approval.v1"

# A recovery request is valid for 7 days after the node signed its assertion.
# The node deletes older requests and their approvals; guardians refuse them.
RECOVERY_REQUEST_MAX_AGE = 7 * 86400  # seconds

MAX_GUARDIANS = 16


def guardian_info(set_id: bytes, index: int, device_ed25519: bytes) -> bytes:
    return tagged_message(TAG_HPKE_GUARDIAN, set_id + bytes([index]) + device_ed25519)


def recovery_info(request_id: bytes, index: int) -> bytes:
    return tagged_message(TAG_HPKE_RECOVERY, request_id + bytes([index]))


def make_share(
    *, owner: str, set_id: bytes, index: int, threshold: int, backup_id: str, share: bytes
) -> dict:
    doc = {
        "backup_id": backup_id,
        "index": index,
        "owner": owner,
        "schema": GUARDIAN_SHARE_SCHEMA,
        "set_id": set_id.hex(),
        "share": share.hex(),
        "threshold": threshold,
    }
    return validate_share(doc)


def validate_share(doc: Any) -> dict:
    names = {"backup_id", "index", "owner", "schema", "set_id", "share", "threshold"}
    exact_fields(doc, names, "guardian share")
    if doc["schema"] != GUARDIAN_SHARE_SCHEMA:
        raise FormatError("guardian share: unknown schema")
    hex_field(doc["backup_id"], HEX32, "backup_id")
    hex_field(doc["set_id"], HEX16, "set_id")
    hex_field(doc["share"], HEX32, "share")
    int_in(doc["index"], 1, MAX_GUARDIANS, "index")
    int_in(doc["threshold"], 2, MAX_GUARDIANS, "threshold")
    validate_subject(doc["owner"])
    return doc


def validate_guardian_set(doc: Any) -> dict:
    names = {"backup_id", "created_at", "guardians", "schema", "set_id", "subject", "threshold"}
    exact_fields(doc, names, "guardian set")
    if doc["schema"] != GUARDIAN_SET_SCHEMA:
        raise FormatError("guardian set: unknown schema")
    hex_field(doc["backup_id"], HEX32, "backup_id")
    hex_field(doc["set_id"], HEX16, "set_id")
    validate_subject(doc["subject"])
    parse_time(doc["created_at"])
    g = doc["guardians"]
    if not isinstance(g, list) or not 2 <= len(g) <= MAX_GUARDIANS:
        raise FormatError("guardian set: need 2 to 16 guardians")
    int_in(doc["threshold"], 2, len(g), "threshold")
    subjects = []
    for i, item in enumerate(g, start=1):
        exact_fields(item, {"index", "subject", "wraps"}, "guardian")
        if item["index"] != i:
            raise FormatError("guardian set: indices must be 1..n in order")
        subjects.append(validate_subject(item["subject"]))
        validate_wraps(item["wraps"])
    if len(set(subjects)) != len(subjects) or doc["subject"] in subjects:
        raise FormatError("guardian set: guardians must be distinct other people")
    return doc


def make_recovery_request(
    *, subject: str, device: dict, assertion: dict, pop: str, created_at: datetime
) -> dict:
    doc = {
        "assertion": assertion,
        "created_at": format_time(created_at),
        "device": device,
        "pop": pop,
        "schema": RECOVERY_REQUEST_SCHEMA,
        "subject": subject,
    }
    return validate_recovery_request(doc)


def validate_recovery_request(doc: Any) -> dict:
    exact_fields(doc, {"assertion", "created_at", "device", "pop", "schema", "subject"}, "request")
    if doc["schema"] != RECOVERY_REQUEST_SCHEMA:
        raise FormatError("recovery request: unknown schema")
    validate_subject(doc["subject"])
    parse_time(doc["created_at"])
    exact_fields(doc["device"], {"ed25519", "x25519"}, "device")
    hex_field(doc["device"]["ed25519"], HEX32, "device")
    hex_field(doc["device"]["x25519"], HEX32, "device")
    hex_field(doc["pop"], HEX64, "pop")
    if not isinstance(doc["assertion"], dict):
        raise FormatError("recovery request: bad assertion")
    return doc


def recovery_request_id(doc: dict) -> str:
    return tagged_hash(TAG_RECOVERY_REQUEST_ID, canonical_json(doc))[:16].hex()


def validate_approval(doc: Any) -> dict:
    exact_fields(doc, {"ciphertext", "guardian", "index", "request_id", "schema"}, "approval")
    if doc["schema"] != GUARDIAN_APPROVAL_SCHEMA:
        raise FormatError("approval: unknown schema")
    b64_field(doc["ciphertext"], "ciphertext")
    validate_subject(doc["guardian"])
    int_in(doc["index"], 1, MAX_GUARDIANS, "index")
    hex_field(doc["request_id"], HEX16, "request_id")
    return doc
