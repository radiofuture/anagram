"""The lab item (spec/lab.md): a signed value in a lab space record. A
lab item is a finding, a note, or a source item that a member publishes to
the lab. Its text is in separate records of at most 1 MiB each."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from anagram.core.canonical import JsonObject
from anagram.core.crypto.hashing import TAG_LAB_ITEM, TAG_SIGN_LAB_ITEM, tagged_message
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.core.signed import doc_signature_ok, sign_doc
from anagram.core.timefmt import format_time, parse_time
from anagram.core.validate import HEX16, HEX32, HEX64, hex_field, int_at_least
from anagram.identity.api import validate_lab_id, validate_subject
from anagram.network.formats.lab import check_roster_ref, check_text

ITEM_SCHEMA = "anagram.lab_item.v1"
ITEM_KINDS = ("finding", "note", "source_item")
KIND_ITEM = "lab_item"
KIND_ITEM_TEXT = "lab_item_text"
MAX_TEXT_PART = 1 << 20  # UTF-8 bytes of text in one record
MAX_TITLE = 500
MAX_FACTS = 200
MAX_ATTACHMENTS = 64
_ITEM_FIELDS = {
    "schema",
    "lab_id",
    "item_id",
    "rev",
    "kind",
    "type",
    "title",
    "author",
    "author_device",
    "published_at",
    "updated_at",
    "origin",
    "text_parts",
    "text_digest",
    "facts",
    "finding",
    "attachments",
    "roster",
    "deleted",
    "signature",
}
_ATTACH_FIELDS = {
    "blob_id",
    "name",
    "media_type",
    "size",
    "chunk_size",
    "slot",
    "evidence_root",
    "content_key",
}


def text_digest(text: str) -> str:
    """The SHA-256 (hex) of the UTF-8 text of an item."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def split_text(text: str) -> list[str]:
    """Parts of at most 1 MiB of UTF-8 each, cut at character boundaries."""
    raw = text.encode("utf-8")
    parts, start = [], 0
    while start < len(raw):
        end = min(start + MAX_TEXT_PART, len(raw))
        while end < len(raw) and (raw[end] & 0xC0) == 0x80:
            end -= 1
        parts.append(raw[start:end].decode("utf-8"))
        start = end
    return parts


def part_ref(item_id: str, n: int) -> str:
    """The record reference of text part `n` of an item."""
    return f"{item_id}:{n}"


def attachment_root(lab_id: str, item_id: str) -> bytes:
    """The 32-byte value that binds the chunks of an attachment blob to its
    lab item (the `finding_root` input of `crypto.blob`). The `evidence_root`
    input is the attachment's `evidence_root`, or 32 zero bytes when null."""
    return hashlib.sha256(tagged_message(TAG_LAB_ITEM, f"{lab_id}/{item_id}".encode())).digest()


def _score_ok(score: Any) -> bool:
    if score is None:
        return True
    return isinstance(score, int) and not isinstance(score, bool) and 0 <= score <= 1000


def _check_origin(origin: Any) -> None:
    if not isinstance(origin, dict) or set(origin) != {"media_type", "name", "source_kind", "time"}:
        raise FormatError("lab item: bad origin (no path and no source ID)")
    for name in ("media_type", "name", "source_kind"):
        check_text(origin[name], f"lab item origin {name}", MAX_TITLE)
    if origin["time"] is not None:
        parse_time(origin["time"])


def _check_facts(facts: Any) -> None:
    if not isinstance(facts, list) or len(facts) > MAX_FACTS:
        raise FormatError("lab item: bad facts")
    for f in facts:
        if not isinstance(f, dict) or set(f) != {"kind", "score", "value"}:
            raise FormatError("lab item: bad fact")
        check_text(f["kind"], "fact kind", 64, optional=False)
        check_text(f["value"], "fact value", 2000, optional=False)
        if not _score_ok(f["score"]):
            raise FormatError("lab item: a fact score is an integer 0..1000 (per mille) or null")


def _check_finding(finding: Any) -> None:
    if finding is None:
        return
    names = {"bundle", "claim", "finding_id", "root", "version"}
    if not isinstance(finding, dict) or set(finding) != names:
        raise FormatError("lab item: bad finding")
    hex_field(finding["root"], HEX32, "lab item finding root")
    check_text(finding["finding_id"], "lab item finding_id", 200, optional=False)
    int_at_least(finding["version"], "lab item finding version", 1)
    if finding["claim"] is not None and not isinstance(finding["claim"], str):
        raise FormatError("lab item: bad claim")
    if not isinstance(finding["bundle"], dict):
        raise FormatError("lab item: the finding needs its public proof bundle")


def _check_attachments(atts: Any) -> None:
    if not isinstance(atts, list) or len(atts) > MAX_ATTACHMENTS:
        raise FormatError("lab item: bad attachments")
    for a in atts:
        if not isinstance(a, dict) or set(a) != _ATTACH_FIELDS:
            raise FormatError("lab item: bad attachment")
        hex_field(a["blob_id"], HEX16, "attachment blob_id")
        hex_field(a["content_key"], HEX32, "attachment content_key")
        if a["evidence_root"] is not None:
            hex_field(a["evidence_root"], HEX32, "attachment evidence_root")
        check_text(a["name"], "attachment name", MAX_TITLE, optional=False)
        check_text(a["media_type"], "attachment media_type", 200, optional=False)
        for name in ("size", "chunk_size", "slot"):
            int_at_least(a[name], f"attachment {name}")


def validate_lab_item(doc: Any) -> JsonObject:
    """Check the form of a lab item (not its signature; see `verify_lab_item`)."""
    if not isinstance(doc, dict) or set(doc) != _ITEM_FIELDS:
        raise FormatError("lab item: fields do not match the schema")
    if doc["schema"] != ITEM_SCHEMA:
        raise FormatError("lab item: unknown schema")
    validate_lab_id(doc["lab_id"])
    hex_field(doc["item_id"], HEX16, "lab item item_id")
    int_at_least(doc["rev"], "lab item rev", 1)
    if doc["kind"] not in ITEM_KINDS:
        raise FormatError("lab item: unknown kind")
    check_text(doc["type"], "lab item type", 64)
    check_text(doc["title"], "lab item title", MAX_TITLE, optional=False)
    validate_subject(doc["author"])
    hex_field(doc["author_device"], HEX32, "lab item author_device")
    parse_time(doc["published_at"])
    parse_time(doc["updated_at"])
    _check_origin(doc["origin"])
    int_at_least(doc["text_parts"], "lab item text_parts")
    hex_field(doc["text_digest"], HEX32, "lab item text_digest")
    _check_facts(doc["facts"])
    _check_finding(doc["finding"])
    _check_attachments(doc["attachments"])
    check_roster_ref(doc["roster"], "lab item")
    if not isinstance(doc["deleted"], bool):
        raise FormatError("lab item: deleted is true or false")
    has_content = doc["text_parts"] or doc["attachments"] or doc["facts"]
    if doc["deleted"] and (has_content or doc["finding"] is not None):
        raise FormatError("lab item: a removed item has no text, facts, finding, or files")
    hex_field(doc["signature"], HEX64, "lab item signature")
    return doc


def make_lab_item(
    *,
    lab_id: str,
    item_id: str,
    rev: int,
    kind: str,
    title: str,
    text: str,
    author: str,
    key: SigningKey,
    roster: JsonObject,
    published_at: datetime,
    updated_at: datetime,
    origin: JsonObject | None = None,
    type: str | None = None,  # the field name of the format
    facts: Sequence[JsonObject] = (),
    finding: JsonObject | None = None,
    attachments: Sequence[JsonObject] = (),
    deleted: bool = False,
) -> JsonObject:
    """A signed lab item value. For a removed item (`deleted`), `author` is
    the person who removes it (the author, the PI, or an admin)."""
    origin = origin or {}
    doc = {
        "attachments": list(attachments),
        "author": author,
        "author_device": key.public_bytes().hex(),
        "deleted": deleted,
        "facts": list(facts),
        "finding": finding,
        "item_id": item_id,
        "kind": kind,
        "lab_id": lab_id,
        "origin": {
            "media_type": origin.get("media_type"),
            "name": origin.get("name"),
            "source_kind": origin.get("source_kind"),
            "time": origin.get("time"),
        },
        "published_at": format_time(published_at),
        "rev": rev,
        "roster": roster,
        "schema": ITEM_SCHEMA,
        "text_digest": text_digest(text),
        "text_parts": len(split_text(text)),
        "title": title,
        "type": type,
        "updated_at": format_time(updated_at),
    }
    doc["signature"] = sign_doc(doc, TAG_SIGN_LAB_ITEM, key)
    return validate_lab_item(doc)


def verify_lab_item(doc: Any) -> JsonObject:
    """Form and the signature of the author device. The caller checks that
    the device is a key of the author and that the author can write it."""
    checked = validate_lab_item(doc)
    if not doc_signature_ok(doc, TAG_SIGN_LAB_ITEM, bytes.fromhex(doc["author_device"])):
        raise FormatError("lab item: bad signature")
    return checked
