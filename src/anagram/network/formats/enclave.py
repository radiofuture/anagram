"""Messages between app, node and enclave (spec/enclave-messages.md)."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from anagram.core.canonical import CanonicalError, JsonObject, canonical_json, loads_canonical
from anagram.core.crypto import hpke
from anagram.core.crypto.hashing import tagged_hash, tagged_message, u32
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats import credential as cred
from anagram.network.formats import pack as packs
from anagram.network.formats.strict import (
    DAY,
    HEX16,
    HEX32,
    MAX_SAFE,
    NODE_ID,
    ROR,
    Refused,
    check_x25519_public,
    enum,
    exact,
    fmt_time,
    hexval,
    intval,
    need,
    pad,
    parse_time,
    sig_ok,
    sign,
    text,
    unpad,
)

MAGIC = b"AGE1"
HEADER = 101
RESPONSE = slice(69, 101)  # the response key in the header (3.1)
ENC = 32
TAG_LEN = 16
CLASS_UPLOAD, CLASS_KNOWN, CLASS_ANSWER = 1, 2, 3
SIZES = {CLASS_UPLOAD: 65_536, CLASS_KNOWN: 393_216, CLASS_ANSWER: 2_048}


class BadLength(Refused):
    """A sealed request whose length is not the length of its route's class
    (`400` at the node relay and at the enclave, 9.2)."""

    def __init__(self) -> None:
        super().__init__("bad_length", "wrong body length")


def check_length(cls: int, body: bytes) -> None:
    if len(body) != SIZES[cls]:
        raise BadLength


RECEIPT_SIZE = 1_024
SLOT_SIZE = 4_096
SLOT_DAYS = 28  # 6.3: a node keeps a slot 28 days: the 22 days of a proposal and a margin
CHECKPOINTS = 3  # 5.3: answers leave at three checkpoints
FILLER_SCHEMA = "anagram.enclave.answer_filler.v1"

TAG_HPKE_REQUEST = "anagram/v1/enclave/hpke/request"
TAG_HPKE_RECEIPT = "anagram/v1/enclave/hpke/receipt"
TAG_HPKE_SLOT = "anagram/v1/enclave/hpke/slot"
TAG_REQUEST = "anagram/v1/enclave/request"
TAG_SLOT = "anagram/v1/enclave/slot"
TAG_SLOT_FILLER = b"anagram/v1/enclave/slot-filler"
TAG_RECEIPT_FILLER = b"anagram/v1/enclave/receipt-filler"
TAG_SIGN_RECEIPT = "anagram/v1/enclave/sign/receipt"
TAG_SIGN_SLOT = "anagram/v1/enclave/sign/slot"
TAG_SIGN_ANSWER = "anagram/v1/enclave/sign/answer"
TAG_SIGN_WITHDRAWAL = "anagram/v1/enclave/sign/withdrawal"
TAG_SIGN_COVER = "anagram/v1/enclave/sign/cover"
TAG_SIGN_NODE_REQUEST = "anagram/v1/net/sign/node-request"

ERRORS = (
    "bad_envelope",
    "stale_attestation",
    "unknown_instance_key",
    "bad_message",
    "unsupported_schema",
    "bad_signature",
    "bad_credential",
    "revoked",
    "expired",
    "old_version",
    "tombstoned",
    "rate_limited",
    "too_large",
    "unknown_proposal",
    "already_answered",
    "stale_roster",
    "clock_unsafe",
    "unavailable",
    "wrong_shard",
    "issuance_limit",
)
CHOICES = ("no", "not_now", "yes")
ORCID = re.compile(r"^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$")
EMAIL = re.compile(r"^[!-?A-~]{1,64}@[a-z0-9.-]{1,189}$")
CARD_MAX = 1_200


def plaintext_size(cls: int) -> int:
    return SIZES[cls] - HEADER - ENC - TAG_LEN


def header(cls: int, attestation: bytes, intake: bytes, response: bytes) -> bytes:
    need(len(attestation) == len(intake) == len(response) == 32, "bad_envelope", "header")
    return MAGIC + bytes([cls]) + attestation + intake + response


def request_info(head: bytes) -> bytes:
    return tagged_message(TAG_HPKE_REQUEST, head)


def seal_request(
    cls: int, attestation: bytes, intake: bytes, response: bytes, body: bytes
) -> bytes:
    head = header(cls, attestation, intake, response)
    sealed = hpke.seal(intake, pad(body, plaintext_size(cls)), request_info(head))
    out = head + sealed
    need(len(out) == SIZES[cls], "bad_envelope", "size")
    return out


@dataclass(frozen=True)
class Request:
    cls: int
    attestation: bytes
    intake: bytes
    response: bytes
    digest: bytes


def parse_header(raw: bytes) -> Request:
    need(len(raw) >= HEADER and raw[:4] == MAGIC, "bad_envelope", "magic")
    cls = raw[4]
    need(cls in SIZES and len(raw) == SIZES[cls], "bad_envelope", "class or size")
    response = check_x25519_public(raw[RESPONSE], "bad_envelope", "response key")
    return Request(cls, raw[5:37], raw[37:69], response, request_digest(raw))


def open_request(
    raw: bytes, keys: Mapping[bytes, X25519PrivateKey], attestation: Mapping[bytes, bytes]
) -> tuple[Request, bytes]:
    """`keys`: intake public key -> private key; `attestation`: intake key -> digest."""
    req = parse_header(raw)
    priv = keys.get(req.intake)
    if priv is None:
        raise Refused("unknown_instance_key")
    need(attestation.get(req.intake) == req.attestation, "stale_attestation")
    try:
        padded = hpke.open_sealed(priv, raw[HEADER:], request_info(raw[:HEADER]))
    except InvalidTag as exc:
        raise Refused("bad_envelope", "decrypt") from exc
    return req, unpad(padded)


def request_digest(raw: bytes) -> bytes:
    return tagged_hash(TAG_REQUEST, raw)


# Receipts.


def receipt(
    status: str, reason: str | None, digest: bytes, now: int, key: SigningKey
) -> JsonObject:
    need(status in ("accepted", "rejected"), "bad_message", "status")
    need((reason is None) == (status == "accepted"), "bad_message", "reason")
    need(reason is None or reason in ERRORS, "bad_message", "reason")
    doc = {
        "reason": reason,
        "request": digest.hex(),
        "schema": "anagram.enclave.receipt.v1",
        "signer": key.public_bytes().hex(),
        "status": status,
        "time": fmt_time(now),
    }
    return sign(doc, TAG_SIGN_RECEIPT, key)


def seal_receipt(response: bytes, digest: bytes, doc: JsonObject) -> bytes:
    info = tagged_message(TAG_HPKE_RECEIPT, digest)
    out = hpke.seal(response, pad(canonical_json(doc), RECEIPT_SIZE - ENC - TAG_LEN), info)
    need(len(out) == RECEIPT_SIZE, "bad_message", "receipt size")
    return out


def open_receipt(private: Any, digest: bytes, raw: bytes, output_keys: set[str]) -> JsonObject:
    """The app side. `output_keys`: logged output keys of live instances."""
    need(len(raw) == RECEIPT_SIZE, "bad_envelope", "receipt size")
    try:
        body = unpad(hpke.open_sealed(private, raw, tagged_message(TAG_HPKE_RECEIPT, digest)))
    except InvalidTag as exc:
        raise Refused("bad_envelope", "receipt decrypt") from exc
    doc = read_json(body)
    exact(doc, {"reason", "request", "schema", "signature", "signer", "status", "time"}, "receipt")
    need(doc["signer"] in output_keys, "bad_signature", "receipt signer")
    need(sig_ok(doc, TAG_SIGN_RECEIPT, doc["signer"]), "bad_signature", "receipt")
    need(doc["request"] == digest.hex(), "bad_message", "receipt request")
    return doc


def read_json(body: bytes) -> JsonObject:
    try:
        doc = loads_canonical(body)
    except (CanonicalError, ValueError) as exc:
        raise Refused("bad_message", "not canonical JSON") from exc
    if not isinstance(doc, dict):
        raise Refused("bad_message", "object")
    return doc


# Slots.


def slot_address(day: int, reply_key: bytes) -> bytes:
    return tagged_hash(TAG_SLOT, u32(day) + reply_key)


def slot_info(day: int, address: bytes) -> bytes:
    return tagged_message(TAG_HPKE_SLOT, u32(day) + address)


def slot_doc(day: int, item: JsonObject, key: SigningKey) -> JsonObject:
    check_item(item)
    doc = {
        "day": day,
        "item": item,
        "schema": "anagram.enclave.slot.v1",
        "signer": key.public_bytes().hex(),
    }
    return sign(doc, TAG_SIGN_SLOT, key)


def seal_slot(reply_key: bytes, day: int, doc: JsonObject) -> bytes:
    address = slot_address(day, reply_key)
    padded = pad(canonical_json(doc), SLOT_SIZE - ENC - TAG_LEN)
    out = hpke.seal(reply_key, padded, slot_info(day, address))
    need(len(out) == SLOT_SIZE, "bad_message", "slot size")
    return out


def open_slot(private: Any, day: int, raw: bytes, output_keys: set[str]) -> JsonObject | None:
    """Return the slot document, or None for bytes that do not open (a filler)."""
    reply_key = hpke.public_bytes(private)
    try:
        padded = hpke.open_sealed(private, raw, slot_info(day, slot_address(day, reply_key)))
    except InvalidTag:
        return None
    doc = read_json(unpad(padded))
    exact(doc, {"day", "item", "schema", "signature", "signer"}, "slot")
    need(doc["day"] == day and doc["schema"] == "anagram.enclave.slot.v1", "bad_message", "slot")
    need(doc["signer"] in output_keys, "bad_signature", "slot signer")
    need(sig_ok(doc, TAG_SIGN_SLOT, doc["signer"]), "bad_signature", "slot")
    check_item(doc["item"])
    return doc


ITEM_FIELDS = {
    "empty": {"kind"},
    "proposal": {
        "checkpoints",
        "expires",
        "id",
        "kind",
        "pack_version",
        "protocol",
        "reasons",
        "type",
    },
    "reveal": {"card", "kind", "known", "node", "peer", "proposal", "type"},
    "ended": {"kind", "proposal"},
}
LINE_REF = re.compile(r"^[ow](0[1-9]|1[0-9]|20)$")


def check_item(item: Any) -> None:
    need(isinstance(item, dict), "bad_message", "item")
    kind = enum(item.get("kind"), tuple(ITEM_FIELDS), "item kind")
    exact(item, ITEM_FIELDS[kind], f"{kind} item")
    if kind == "proposal":
        hexval(item["id"], HEX16, "proposal id")
        _check_plan(item["checkpoints"], item["expires"])
        intval(item["pack_version"], 1, MAX_SAFE, "pack_version")
        enum(item["type"], packs.TYPES, "type")
        need(item["protocol"] == f"anagram.fit.{item['type']}.v1", "bad_message", "protocol")
        reasons = item["reasons"]
        need(isinstance(reasons, list) and 1 <= len(reasons) <= 4, "bad_message", "reasons")
        need(reasons == sorted(set(reasons)), "bad_message", "reason order")
        for r in reasons:
            hexval(r, LINE_REF, "reason")
    elif kind == "reveal":
        hexval(item["proposal"], HEX16, "proposal")
        hexval(item["peer"], HEX32, "peer")
        enum(item["type"], packs.TYPES, "type")
        need(isinstance(item["known"], bool), "bad_message", "known")
        check_card(item["card"])
        check_reveal_node(item["node"])
    elif kind == "ended":
        hexval(item["proposal"], HEX16, "proposal")


def _check_plan(checkpoints: Any, expires: Any) -> None:
    """Three checkpoints at 00:00 UTC, evenly spaced and ascending, and the
    expiry at the end of the last checkpoint day (section 5.3)."""
    need(
        isinstance(checkpoints, list) and len(checkpoints) == CHECKPOINTS,
        "bad_message",
        "checkpoints",
    )
    days = []
    for value in checkpoints:
        t = parse_time(value, "checkpoint")
        need(t % DAY == 0, "bad_message", "checkpoint at 00:00 UTC")
        days.append(t // DAY)
    step = days[1] - days[0]
    need(step >= 1 and days[2] - days[1] == step, "bad_message", "checkpoint spacing")
    need(parse_time(expires, "expires") == (days[-1] + 1) * DAY, "bad_message", "expires")


def check_reveal_node(node: Any) -> None:
    """The peer's node as the roster names it (W4 finding M-h): the enclave
    adds it, so the app can show a verified affiliation next to the card."""
    exact(node, {"affiliation", "id", "ror"}, "reveal node")
    hexval(node["id"], NODE_ID, "node id")
    text(node["affiliation"], 200, "affiliation")
    need(node["ror"] is None or bool(ROR.match(str(node["ror"]))), "bad_message", "ror")


def filler(node_secret: bytes, address: bytes) -> bytes:
    """The bytes for an address with no slot (spec section 6.3)."""
    return _filler(node_secret, address, TAG_SLOT_FILLER, SLOT_SIZE)


def receipt_filler(node_secret: bytes, digest: bytes) -> bytes:
    """The bytes for a request digest with no receipt yet (spec section 4.4)."""
    return _filler(node_secret, digest, TAG_RECEIPT_FILLER, RECEIPT_SIZE)


def _filler(node_secret: bytes, name: bytes, info: bytes, size: int) -> bytes:
    prk = hmac.new(node_secret, name, hashlib.sha256).digest()
    return HKDFExpand(hashes.SHA256(), size, info).derive(prk)


def slot_batch(day: int, slots: dict[bytes, bytes]) -> bytes:
    out = bytearray(u32(day) + u32(len(slots)))
    for address in sorted(slots):
        need(len(slots[address]) == SLOT_SIZE, "bad_message", "slot size")
        out += address + slots[address]
    return bytes(out)


def read_batch(raw: bytes) -> tuple[int, dict[bytes, bytes]]:
    need(len(raw) >= 8, "bad_message", "batch")
    day, count = int.from_bytes(raw[:4], "big"), int.from_bytes(raw[4:8], "big")
    need(len(raw) == 8 + count * (32 + SLOT_SIZE), "bad_message", "batch length")
    out = {}
    for i in range(count):
        at = 8 + i * (32 + SLOT_SIZE)
        out[raw[at : at + 32]] = raw[at + 32 : at + 32 + SLOT_SIZE]
    need(list(out) == sorted(out) and len(out) == count, "bad_message", "batch order")
    return day, out


# Answers, withdrawals, cover.


def check_card(card: Any) -> None:
    exact(card, {"email", "institution", "lab", "name", "orcid"}, "card")
    need(
        isinstance(card["email"], str) and bool(EMAIL.match(card["email"])), "bad_message", "email"
    )
    text(card["name"], 200, "name")
    text(card["institution"], 200, "institution")
    need(card["lab"] is None or bool(text(card["lab"], 200, "lab")), "bad_message", "lab")
    need(card["orcid"] is None or bool(ORCID.match(str(card["orcid"]))), "bad_message", "orcid")
    need(len(canonical_json(card)) <= CARD_MAX, "too_large", "card")


def answer_filler() -> JsonObject:
    """What the app sends at an answer checkpoint with no answer to send
    (section 5.3). It has the size of an answer once sealed, so the
    node sees one answer object at each checkpoint of each proposal. It
    names nothing: the enclave keeps nothing for it."""
    return {"schema": FILLER_SCHEMA}


def answer_kind(body: bytes) -> tuple[str, JsonObject]:
    """The kind of an answer-class body: `answer` or `filler`."""
    doc = read_json(body)
    kinds = {"anagram.enclave.answer.v1": "answer", FILLER_SCHEMA: "filler"}
    schema = doc.get("schema")
    if not (isinstance(schema, str) and schema in kinds):  # a list or dict is not hashable
        raise Refused("unsupported_schema", str(schema))
    if kinds[schema] == "filler":
        exact(doc, {"schema"}, "answer filler")
    return kinds[schema], doc


def answer(
    subject: SigningKey, proposal: str, choice: str, created: int, card: JsonObject | None
) -> JsonObject:
    doc = {
        "card": card,
        "choice": choice,
        "created": fmt_time(created),
        "proposal": proposal,
        "schema": "anagram.enclave.answer.v1",
        "subject": subject.public_bytes().hex(),
    }
    return sign(doc, TAG_SIGN_ANSWER, subject)


def check_answer(doc: Any, email_tags: tuple[str, ...] = ()) -> JsonObject:
    names = {"card", "choice", "created", "proposal", "schema", "signature", "subject"}
    checked = exact(doc, names, "answer")
    enum(doc["choice"], CHOICES, "choice")
    hexval(doc["proposal"], HEX16, "proposal")
    hexval(doc["subject"], HEX32, "subject")
    parse_time(doc["created"], "created")
    if doc["choice"] == "yes":
        check_card(doc["card"])
        if email_tags:
            tag = packs.known_tag(packs.email_id(doc["card"]["email"])).hex()
            need(tag in email_tags, "bad_message", "card email is not the verified one")
    else:
        need(doc["card"] is None, "bad_message", "card only with yes")
    need(sig_ok(doc, TAG_SIGN_ANSWER, doc["subject"]), "bad_signature", "answer")
    return checked


def withdrawal(subject: SigningKey, version: int, reply_key: bytes, created: int) -> JsonObject:
    """Matching off (spec section 7.1). It carries the reply key so that the
    subject keeps its slots, like a cover (W4 re-check R1)."""
    doc = {
        "created": fmt_time(created),
        "reply_key": reply_key.hex(),
        "schema": "anagram.enclave.withdrawal.v1",
        "subject": subject.public_bytes().hex(),
        "version": version,
    }
    return sign(doc, TAG_SIGN_WITHDRAWAL, subject)


def check_withdrawal(doc: Any) -> JsonObject:
    checked = exact(
        doc, {"created", "reply_key", "schema", "signature", "subject", "version"}, "withdrawal"
    )
    hexval(doc["subject"], HEX32, "subject")
    check_x25519_public(
        bytes.fromhex(hexval(doc["reply_key"], HEX32, "reply_key")), "bad_message", "reply_key"
    )
    intval(doc["version"], 1, MAX_SAFE, "version")
    parse_time(doc["created"], "created")
    need(sig_ok(doc, TAG_SIGN_WITHDRAWAL, doc["subject"]), "bad_signature", "withdrawal")
    return checked


def cover(
    subject: SigningKey, kind: str, credential: JsonObject, reply_key: bytes, created: int
) -> JsonObject:
    """The upload of an app with matching off (spec section 7.2)."""
    doc = {
        "created": fmt_time(created),
        "credential": credential,
        "kind": kind,
        "reply_key": reply_key.hex(),
        "schema": "anagram.enclave.cover.v1",
        "subject": subject.public_bytes().hex(),
    }
    return sign(doc, TAG_SIGN_COVER, subject)


def check_cover(doc: Any, ctx: packs.Context) -> cred.MemberFacts:
    """Field, signature and credential checks of a cover. A cover needs no
    consent and no version: it changes no matching state."""
    names = {"created", "credential", "kind", "reply_key", "schema", "signature", "subject"}
    exact(doc, names, "cover")
    hexval(doc["subject"], HEX32, "subject")
    check_x25519_public(
        bytes.fromhex(hexval(doc["reply_key"], HEX32, "reply_key")), "bad_message", "reply_key"
    )
    enum(doc["kind"], ("group", "person"), "kind")
    packs.check_age(parse_time(doc["created"], "created"), ctx.now)
    need(sig_ok(doc, TAG_SIGN_COVER, doc["subject"]), "bad_signature", "cover")
    return packs.check_credential(doc, ctx)


def upload_kind(body: bytes) -> str:
    doc = read_json(body)
    schema = doc.get("schema")
    kinds = {
        "anagram.pack.v1": "pack",
        "anagram.enclave.withdrawal.v1": "withdrawal",
        "anagram.enclave.cover.v1": "cover",
    }
    if not (isinstance(schema, str) and schema in kinds):  # a list or dict is not hashable
        raise Refused("unsupported_schema", str(schema))
    return kinds[schema]


# The node request signature (node -> enclave).


NODE_NONCE = 16  # bytes; the replay key is (node, nonce)


def node_request_payload(
    node: str, audience: str, method: str, path: str, time: int, body: bytes, nonce: bytes
) -> bytes:
    """`audience` is the origin of the service that gets the request (the
    enclave log origin, or the roster service): the signature names its
    target, so a request for one service is not valid at another (W4 Low).
    `nonce` is 16 random bytes for each request: two equal requests in the
    same second are two requests, and the service refuses a second use of
    (node, nonce) as a replay."""
    if len(nonce) != NODE_NONCE:
        raise ValueError("a node request nonce has 16 bytes")
    return canonical_json(
        {
            "body": hashlib.sha256(body).hexdigest(),
            "audience": audience,
            "method": method,
            "node": node,
            "nonce": nonce.hex(),
            "path": path,
            "time": fmt_time(time),
        }
    )
