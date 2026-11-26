"""Sealed requests, receipts, slots, answers, withdrawals, covers and the
node request signature (enclave-messages.md 3 to 9)."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .core import (
    Refused,
    Signer,
    cjson,
    filler,
    fmt_time,
    hpke_open,
    hpke_seal,
    is_hex,
    is_text,
    pad,
    parse_canonical,
    parse_time,
    sha256,
    tagged_hash,
    tagged_message,
    u32,
    unpad,
    verify_doc,
    x25519_public,
)

MAGIC = b"AGE1"
UPLOAD, KNOWN, ANSWER = 1, 2, 3
SIZE = {UPLOAD: 65_536, KNOWN: 393_216, ANSWER: 2_048}
RECEIPT_SIZE = 1_024
SLOT_SIZE = 4_096
ERRORS = (
    "bad_envelope", "stale_attestation", "unknown_instance_key", "bad_message",
    "unsupported_schema", "bad_signature", "bad_credential", "revoked", "expired",
    "old_version", "tombstoned", "rate_limited", "too_large", "unknown_proposal",
    "already_answered", "stale_roster", "clock_unsafe", "unavailable", "wrong_shard",
    "issuance_limit",
)  # fmt: skip


@dataclass
class Sealed:
    request: bytes
    digest: str
    response_private: bytes
    header: bytes


def header(cls: int, attestation: str, intake: bytes, response_public: bytes) -> bytes:
    return MAGIC + bytes([cls]) + bytes.fromhex(attestation) + intake + response_public


def request_info(h: bytes) -> bytes:
    return tagged_message("anagram/v1/enclave/hpke/request", h)


def request_digest(request: bytes) -> str:
    return tagged_hash("anagram/v1/enclave/request", request).hex()


def seal_request(
    cls: int, body: bytes, attestation: str, intake: bytes, response_private: bytes | None = None
) -> Sealed:
    rp = response_private or os.urandom(32)
    h = header(cls, attestation, intake, x25519_public(rp))
    sealed = hpke_seal(intake, pad(body, SIZE[cls] - 149), request_info(h))
    request = h + sealed
    if len(request) != SIZE[cls]:
        raise AssertionError("size")
    return Sealed(request, request_digest(request), rp, h)


def open_request(intake_private: bytes, request: bytes) -> tuple[bytes, bytes] | None:
    """The enclave's open (for vectors): (header, body) or None."""
    h = request[:101]
    plain = hpke_open(intake_private, request[101:], request_info(h))
    if plain is None:
        return None
    body = unpad(plain)
    return None if body is None else (h, body)


# ---- receipts (4) -----------------------------------------------------------------


RECEIPT_FIELDS = {"reason", "request", "schema", "signature", "signer", "status", "time"}


def open_receipt(sealed: Sealed, raw: bytes, output_keys: set[str]) -> dict | None:
    """4.3: the receipt document, or None for "no receipt"."""
    if len(raw) != RECEIPT_SIZE:
        return None
    info = tagged_message("anagram/v1/enclave/hpke/receipt", bytes.fromhex(sealed.digest))
    plain = hpke_open(sealed.response_private, raw, info)
    body = unpad(plain) if plain is not None else None
    if body is None:
        return None
    try:
        doc = parse_canonical(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict) or set(doc) != RECEIPT_FIELDS:
        return None
    if doc["request"] != sealed.digest or doc["signer"] not in output_keys:
        return None
    if doc["schema"] != "anagram.enclave.receipt.v1":
        return None
    if not verify_doc(doc["signer"], "anagram/v1/enclave/sign/receipt", doc):
        return None
    ok = (doc["status"] == "accepted" and doc["reason"] is None) or (
        doc["status"] == "rejected" and doc["reason"] in ERRORS
    )
    return doc if ok else None


def receipt_filler(node_secret: bytes, digest: str) -> bytes:
    return filler(node_secret, bytes.fromhex(digest), "anagram/v1/enclave/receipt-filler", 1024)


# ---- slots (6) --------------------------------------------------------------------


def slot_address(day: int, reply_public: bytes) -> bytes:
    return tagged_hash("anagram/v1/enclave/slot", u32(day) + reply_public)


def slot_filler(node_secret: bytes, address: bytes) -> bytes:
    return filler(node_secret, address, "anagram/v1/enclave/slot-filler", SLOT_SIZE)


_ITEM_FIELDS = {
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


def item_ok(item: object, day: int) -> bool:
    if not isinstance(item, dict) or item.get("kind") not in _ITEM_FIELDS:
        return False
    if set(item) != _ITEM_FIELDS[item["kind"]]:
        return False
    k = item["kind"]
    if k == "proposal":
        r = item["reasons"]
        return (
            is_hex(item["id"], 16)
            and item["protocol"] == f"anagram.fit.{item['type']}.v1"
            and isinstance(r, list)
            and 1 <= len(r) <= 4
            and r == sorted(set(r))
            and plan_ok(item["checkpoints"], item["expires"], day)
        )
    if k == "reveal":
        return (
            card_ok(item["card"])
            and is_hex(item["peer"], 32)
            and is_hex(item["proposal"], 16)
            and isinstance(item["known"], bool)
            and isinstance(item["node"], dict)
            and set(item["node"]) == {"affiliation", "id", "ror"}
        )
    if k == "ended":
        return is_hex(item["proposal"], 16)
    return True


def answer_plan(made: int, answer_day: int) -> tuple[list[int], int]:
    """5.3: checkpoint days m + a, m + 2a, m + 3a with m = day of `made` + 1;
    the expiry is 00:00 UTC of the day after the last checkpoint."""
    m = made // 86_400 + 1
    days = [m + k * answer_day for k in (1, 2, 3)]
    return days, (days[-1] + 1) * 86_400


def plan_ok(checkpoints: object, expires: object, day: int) -> bool:
    """6.4: three times at 00:00 UTC, equal steps of 1 to 7 days, the first
    after the slot day; `expires` is the day after the last."""
    if not isinstance(checkpoints, list) or len(checkpoints) != 3:
        return False
    try:
        days = [parse_time(c) for c in checkpoints]
        end = parse_time(expires)
    except (ValueError, TypeError):
        return False
    if any(t % 86_400 for t in days):
        return False
    d = [t // 86_400 for t in days]
    step = d[1] - d[0]
    return 1 <= step <= 7 and d[2] - d[1] == step and d[0] > day and end == days[2] + 86_400


def open_slot(reply_private: bytes, day: int, raw: bytes, output_keys: set[str]) -> dict | None:
    """6.2: the slot document, or None (a filler: "nothing for me")."""
    if len(raw) != SLOT_SIZE:
        return None
    address = slot_address(day, x25519_public(reply_private))
    info = tagged_message("anagram/v1/enclave/hpke/slot", u32(day) + address)
    plain = hpke_open(reply_private, raw, info)
    body = unpad(plain) if plain is not None else None
    if body is None:
        return None
    try:
        doc = parse_canonical(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(doc, dict) or set(doc) != {"day", "item", "schema", "signature", "signer"}:
        return None
    if doc["schema"] != "anagram.enclave.slot.v1" or doc["day"] != day:
        return None
    if doc["signer"] not in output_keys:
        return None
    if not verify_doc(doc["signer"], "anagram/v1/enclave/sign/slot", doc):
        return None
    return doc if item_ok(doc["item"], day) else None


# ---- answers, withdrawals, covers (5, 7) ----------------------------------------------

EMAIL = re.compile(r"^[!-?A-~]{1,64}@[a-z0-9.-]{1,189}$")
ORCID = re.compile(r"^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$")


def card_ok(c: object) -> bool:
    if not isinstance(c, dict) or set(c) != {"email", "institution", "lab", "name", "orcid"}:
        return False
    return (
        is_text(c["name"], 200)
        and is_text(c["institution"], 200)
        and (c["lab"] is None or is_text(c["lab"], 200))
        and isinstance(c["email"], str)
        and bool(EMAIL.match(c["email"]))
        and (c["orcid"] is None or (isinstance(c["orcid"], str) and bool(ORCID.match(c["orcid"]))))
        and len(cjson(c)) <= 1200
    )


def answer(subject: Signer, proposal: str, choice: str, card: dict | None, created: int) -> dict:
    doc = {
        "card": card if choice == "yes" else None,
        "choice": choice,
        "created": fmt_time(created),
        "proposal": proposal,
        "schema": "anagram.enclave.answer.v1",
        "subject": subject.hex,
    }
    return subject.sign_doc("anagram/v1/enclave/sign/answer", doc)


def answer_filler() -> dict:
    """5.4: the object an app sends at a checkpoint with no answer to give."""
    return {"schema": "anagram.enclave.answer_filler.v1"}


def withdrawal(subject: Signer, reply_public: bytes, version: int, created: int) -> dict:
    doc = {
        "created": fmt_time(created),
        "reply_key": reply_public.hex(),
        "schema": "anagram.enclave.withdrawal.v1",
        "subject": subject.hex,
        "version": version,
    }
    return subject.sign_doc("anagram/v1/enclave/sign/withdrawal", doc)


def cover(subject: Signer, reply_public: bytes, credential: dict, created: int) -> dict:
    doc = {
        "created": fmt_time(created),
        "credential": credential,
        "kind": "person",
        "reply_key": reply_public.hex(),
        "schema": "anagram.enclave.cover.v1",
        "subject": subject.hex,
    }
    return subject.sign_doc("anagram/v1/enclave/sign/cover", doc)


# ---- node request signature (9.3) ----------------------------------------------------


def node_request_payload(
    audience: str, body: bytes, method: str, node: str, nonce: str, path: str, time: int
) -> bytes:
    return cjson(
        {
            "audience": audience,
            "body": sha256(body).hex(),
            "method": method,
            "node": node,
            "nonce": nonce,
            "path": path,
            "time": fmt_time(time),
        }
    )


def node_headers(
    key: Signer, node: str, audience: str, method: str, path: str, body: bytes, time: int,
    nonce: str | None = None,
) -> dict[str, str]:  # fmt: skip
    n = nonce or os.urandom(16).hex()
    payload = node_request_payload(audience, body, method, node, n, path, time)
    sig = key.sign("anagram/v1/net/sign/node-request", payload)
    return {
        "Anagram-Node": node,
        "Anagram-Time": fmt_time(time),
        "Anagram-Nonce": n,
        "Anagram-Signature": sig.hex(),
    }


def node_id(initial_key: bytes) -> str:
    return "node-" + tagged_hash("anagram/v1/net/node-id", initial_key)[:16].hex()


def check_body_class(cls: int, body: bytes) -> None:
    if len(body) + 4 > SIZE[cls] - 149:
        raise Refused("too_large")
