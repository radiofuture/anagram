"""Sharing formats: read receipt, fetch event, reading copy.
See spec/vault.md sections 12 to 14.

- A read receipt is the reader's signed statement "my device asked to open
  grant G at time T". Only its salted commitment goes into the log (kind
  `read_receipt`). The node must have a receipt before it serves the grant
  ciphertext and its blobs (the receipt gate).
- A fetch event is the node's signed statement "I sent this ciphertext to a
  session of the reader under receipt R". `seq` counts the events of one grant
  from 1, so a removed event shows as a gap.
- The reading copy is derived data (it is never committed): a JSON document
  of blocks that the owner's converters make, encrypted as one more blob with
  a key that only a holder of the content key can compute.

The guest invite, guest key, and guest proof formats are later work
(no guest reader in the release).
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import (
    TAG_READ_RECEIPT,
    TAG_READING_BLOB_ID,
    TAG_READING_EVIDENCE_ROOT,
    TAG_READING_KEY,
    TAG_SIGN_FETCH_EVENT,
    TAG_SIGN_READ_RECEIPT,
    tagged_hash,
    tagged_message,
)
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, exact_fields, hex_field, int_in
from anagram.identity.api import validate_subject
from anagram.proofs.records import KIND_READ_RECEIPT, LOG_ENTRY_SCHEMA

READ_RECEIPT_SCHEMA = "anagram.read_receipt.v1"
FETCH_EVENT_SCHEMA = "anagram.fetch_event.v1"
READING_COPY_SCHEMA = "anagram.reading_copy.v1"

READING_SLOT = 0
READING_COPY_MAX = 8 << 20  # 8 MiB for the whole reading copy
READING_FIGURES_MAX = 6 << 20  # figures go in until this size, then `truncated`
TABLE_ROWS_MAX = 500
VIEWS = ("pdf", "image", "table", "text", "document", "slides", "file")
_MAX_ITEMS = 4096
_MAX_SEQ = 2**53 - 1

_MEDIA = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")
_FIGURE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _text(value: Any, what: str, *, limit: int = 1024, null: bool = False) -> str | None:
    if value is None and null:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise FormatError(f"{what}: bad text")
    return value


# ---------------------------------------------------------------- read receipt


def make_read_receipt(
    *, grant_id: bytes, reader: str, read_at: datetime, salt: bytes, key: SigningKey
) -> JsonObject:
    """The reader's signed statement that one of its devices asked to open the
    grant. `key` is the device signing key of the reader."""
    if len(grant_id) != 16 or len(salt) != 32:
        raise FormatError("read receipt: grant_id is 16 bytes and salt is 32 bytes")
    doc = {
        "grant_id": grant_id.hex(),
        "read_at": format_time(read_at),
        "reader": validate_subject(reader),
        "reader_key": key.public_bytes().hex(),
        "salt": salt.hex(),
        "schema": READ_RECEIPT_SCHEMA,
    }
    doc["signature"] = key.sign(TAG_SIGN_READ_RECEIPT, canonical_json(doc)).hex()
    return validate_read_receipt(doc)


def validate_read_receipt(doc: Any) -> JsonObject:
    names = {"grant_id", "read_at", "reader", "reader_key", "salt", "schema", "signature"}
    checked = exact_fields(doc, names, "read receipt")
    if doc["schema"] != READ_RECEIPT_SCHEMA:
        raise FormatError("read receipt: unknown schema")
    hex_field(doc["grant_id"], HEX16, "grant_id")
    hex_field(doc["reader_key"], HEX32, "reader_key")
    hex_field(doc["salt"], HEX32, "salt")
    hex_field(doc["signature"], HEX64, "signature")
    validate_subject(doc["reader"])
    parse_time(doc["read_at"])
    return checked


def verify_read_receipt(doc: Any) -> JsonObject:
    """Form and signature. The caller checks that `reader_key` is (or was) a
    device key of `reader`."""
    checked = validate_read_receipt(doc)
    if not doc_signature_ok(doc, TAG_SIGN_READ_RECEIPT, bytes.fromhex(doc["reader_key"])):
        raise FormatError("read receipt: bad signature")
    return checked


def read_receipt_commitment(doc: JsonObject) -> bytes:
    return tagged_hash(TAG_READ_RECEIPT, canonical_json(doc))


def read_receipt_id(doc: JsonObject) -> str:
    """The first 16 bytes of the commitment, hex."""
    return read_receipt_commitment(doc)[:16].hex()


def read_receipt_log_entry(doc: JsonObject) -> JsonObject:
    return {
        "commitment": read_receipt_commitment(doc).hex(),
        "kind": KIND_READ_RECEIPT,
        "schema": LOG_ENTRY_SCHEMA,
    }


# ----------------------------------------------------------------- fetch event


def make_fetch_event(
    *,
    at: datetime,
    grant_id: str,
    blob_id: str | None,
    reader: str,
    receipt_id: str,
    seq: int,
    node_key: str,
    key: SigningKey,
) -> JsonObject:
    """The node's signed statement that it served the grant (`blob_id` null) or
    one blob of it to a session of `reader`. `node_key` is the fingerprint of
    the node log key; `key` is the node assertion key."""
    doc = {
        "at": format_time(at),
        "blob_id": blob_id,
        "grant_id": grant_id,
        "node_key": node_key,
        "reader": reader,
        "receipt_id": receipt_id,
        "schema": FETCH_EVENT_SCHEMA,
        "seq": seq,
    }
    validate_fetch_event({**doc, "signature": "00" * 64})
    doc["signature"] = key.sign(TAG_SIGN_FETCH_EVENT, canonical_json(doc)).hex()
    return doc


def validate_fetch_event(doc: Any) -> JsonObject:
    names = {
        "at",
        "blob_id",
        "grant_id",
        "node_key",
        "reader",
        "receipt_id",
        "schema",
        "seq",
        "signature",
    }
    checked = exact_fields(doc, names, "fetch event")
    if doc["schema"] != FETCH_EVENT_SCHEMA:
        raise FormatError("fetch event: unknown schema")
    parse_time(doc["at"])
    if doc["blob_id"] is not None:
        hex_field(doc["blob_id"], HEX16, "blob_id")
    hex_field(doc["grant_id"], HEX16, "grant_id")
    hex_field(doc["node_key"], HEX32, "node_key")
    hex_field(doc["receipt_id"], HEX16, "receipt_id")
    hex_field(doc["signature"], HEX64, "signature")
    validate_subject(doc["reader"])
    int_in(doc["seq"], 1, _MAX_SEQ, "seq")
    return checked


def verify_fetch_event(doc: Any, assertion_key: bytes, node_key: str) -> JsonObject:
    """Form, the node, and the node signature (the pinned assertion key)."""
    checked = validate_fetch_event(doc)
    if doc["node_key"] != node_key:
        raise FormatError("fetch event: from a different node")
    if not doc_signature_ok(doc, TAG_SIGN_FETCH_EVENT, assertion_key):
        raise FormatError("fetch event: bad signature")
    return checked


def seq_gaps(seqs: list[int]) -> list[int]:
    """The numbers that are missing from 1 to max(seqs). A gap shows a fetch
    event that the node removed or did not give."""
    have = set(seqs)
    return [n for n in range(1, max(have, default=0) + 1) if n not in have]


# ---------------------------------------------------------------- reading copy


def reading_key(content_key: bytes, finding_root: bytes) -> bytes:
    """The content key of the reading blob:
    HKDF-SHA256(content_key, info = tagged_message(TAG_READING_KEY, root), L = 32)."""
    if len(content_key) != 32 or len(finding_root) != 32:
        raise FormatError("reading key: content key and root are 32 bytes")
    info = tagged_message(TAG_READING_KEY, finding_root)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(content_key)


def reading_blob_id(content_key: bytes, finding_root: bytes) -> str:
    """Blob ID of the reading copy. Only a holder of the content key can
    compute it."""
    if len(content_key) != 32 or len(finding_root) != 32:
        raise FormatError("reading blob ID: content key and root are 32 bytes")
    return tagged_hash(TAG_READING_BLOB_ID, content_key + finding_root)[:16].hex()


def reading_evidence_root() -> bytes:
    """The fixed evidence root in the AAD of each chunk of the reading blob."""
    return tagged_hash(TAG_READING_EVIDENCE_ROOT, b"")


def _b64(value: Any, what: str) -> bytes:
    try:
        if not isinstance(value, str):
            raise TypeError
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError, binascii.Error) as exc:
        raise FormatError(f"{what}: bad base64") from exc


def _block(b: Any) -> None:
    exact_fields(b, {"anchor", "kind", "level", "parent", "text"}, "block")
    _text(b["anchor"], "block anchor", limit=128)
    _text(b["kind"], "block kind", limit=32)
    int_in(b["level"], 0, 6, "block level")
    _text(b["parent"], "block parent", limit=128, null=True)
    _text(b["text"], "block text", limit=READING_COPY_MAX)


def _table(t: Any) -> None:
    exact_fields(t, {"columns", "rows", "total_rows"}, "table")
    if not isinstance(t["columns"], list) or not isinstance(t["rows"], list):
        raise FormatError("table: columns and rows are lists")
    for c in t["columns"]:
        _text(c, "table column")
    if len(t["rows"]) > TABLE_ROWS_MAX:
        raise FormatError("table: too many rows")
    for row in t["rows"]:
        if not isinstance(row, list):
            raise FormatError("table: a row is a list")
        for cell in row:
            _text(cell, "table cell", limit=65536)
    int_in(t["total_rows"], len(t["rows"]), _MAX_SEQ, "total_rows")


def _item(it: Any) -> int:
    names = {
        "blocks",
        "figures",
        "media_type",
        "name",
        "size",
        "slot",
        "table",
        "truncated",
        "view",
    }
    exact_fields(it, names, "reading item")
    slot = int_in(it["slot"], 0, (1 << 16) - 1, "slot")
    _text(it["name"], "name", limit=255)
    if not isinstance(it["media_type"], str) or not _MEDIA.match(it["media_type"]):
        raise FormatError("media_type: bad value")
    int_in(it["size"], 0, _MAX_SEQ, "size")
    if it["view"] not in VIEWS:
        raise FormatError("view: unknown value")
    if it["blocks"] is not None:
        if not isinstance(it["blocks"], list):
            raise FormatError("blocks: a list or null")
        for b in it["blocks"]:
            _block(b)
    if it["table"] is not None:
        _table(it["table"])
    if not isinstance(it["figures"], list):
        raise FormatError("figures: a list")
    ids = set()
    for f in it["figures"]:
        exact_fields(f, {"data", "id", "media_type"}, "figure")
        if not isinstance(f["id"], str) or not _FIGURE_ID.match(f["id"]) or f["id"] in ids:
            raise FormatError("figure id: bad or repeated value")
        ids.add(f["id"])
        if not isinstance(f["media_type"], str) or not f["media_type"].startswith("image/"):
            raise FormatError("figure media_type: an image type")
        _b64(f["data"], "figure data")
    if type(it["truncated"]) is not bool:
        raise FormatError("truncated: a boolean")
    return slot


def validate_reading_copy(doc: Any) -> JsonObject:
    checked = exact_fields(doc, {"items", "made_by", "schema", "title"}, "reading copy")
    if doc["schema"] != READING_COPY_SCHEMA:
        raise FormatError("reading copy: unknown schema")
    _text(doc["title"], "title", null=True)
    _text(doc["made_by"], "made_by", limit=128)
    if not isinstance(doc["items"], list) or len(doc["items"]) > _MAX_ITEMS:
        raise FormatError("reading copy: bad item list")
    slots = [_item(it) for it in doc["items"]]
    if slots != sorted(set(slots)):
        raise FormatError("reading copy: slots must be sorted and unique")
    if len(canonical_json(doc)) > READING_COPY_MAX:
        raise FormatError("reading copy: larger than 8 MiB")
    return checked
