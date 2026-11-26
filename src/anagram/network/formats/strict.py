"""Shared rules of the enclave formats: refusal codes, text, times, padding."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from anagram.core import timefmt, validate
from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import u32
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.errors import FormatError

HEX32 = validate.HEX32
HEX16 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{128}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,31}$")
NODE_ID = re.compile(r"^node-[0-9a-f]{32}$")
PID = re.compile(r"^pid:[0-9a-f]{32}$")
ROR = re.compile(r"^0[a-z0-9]{6}[0-9]{2}$")
DOMAIN = re.compile(r"^(?=.{1,64}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_U32 = 2**32 - 1
MAX_SAFE = 2**53 - 1
# A signed request (network.md 6.6, enclave-messages.md 9.3): its time is
# within REQUEST_SKEW of the receiver clock, and its nonce is refused again
# for NONCE_MEMORY seconds.
REQUEST_SKEW = 300
NONCE_MEMORY = 600
DAY = 86_400


class Refused(Exception):  # noqa: N818 - the spec word is "refused"
    """A refusal with one error code of the spec (enclave-messages.md,
    enclave-trust.md, network.md). It is the one base of every refusal in
    the network formats and the matching enclave, so a boundary (an HTTP
    route, a ticker) catches `Refused` only, and any other exception is a
    bug. `detail` is for logs and tests; it never holds secret values."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def need(cond: bool, code: str, detail: str = "") -> None:
    if not cond:
        raise Refused(code, detail)


# The checks below raise in the `if` (not with `need`) so that the type
# checker narrows `Any` to the checked type.


def exact(obj: Any, names: set[str], what: str) -> JsonObject:
    if not (isinstance(obj, dict) and set(obj) == names):
        raise Refused("bad_message", f"{what}: fields")
    return obj


def hexval(value: Any, pattern: re.Pattern[str], what: str) -> str:
    if not (isinstance(value, str) and pattern.match(value)):
        raise Refused("bad_message", what)
    return value


def intval(value: Any, lo: int, hi: int, what: str) -> int:
    if not (type(value) is int and lo <= value <= hi):
        raise Refused("bad_message", what)
    return value


def enum(value: Any, allowed: tuple[str, ...], what: str) -> str:
    if not (isinstance(value, str) and value in allowed):
        raise Refused("bad_message", what)
    return value


def text(value: Any, max_chars: int, what: str) -> str:
    """Line, teaser, reading and card text (spec/pack.md section 3.1)."""
    if not isinstance(value, str):
        raise Refused("bad_message", what)
    ok = (
        0 < len(value) <= max_chars
        and unicodedata.normalize("NFC", value) == value
        and value == value.strip()
        and not any(unicodedata.category(c) in ("Cc", "Cs") for c in value)
    )
    need(ok, "bad_message", what)
    return value


def sorted_unique(values: Any, max_len: int, what: str) -> list[Any]:
    if not (isinstance(values, list) and len(values) <= max_len):
        raise Refused("bad_message", what)
    kinds = {type(v) for v in values}
    need(kinds <= {int} or kinds <= {str}, "bad_message", f"{what}: element type")
    need(values == sorted(set(values)), "bad_message", f"{what}: order")
    return values


def concepts(values: Any, max_len: int, what: str) -> list[int]:
    return [intval(v, 0, MAX_U32, what) for v in sorted_unique(values, max_len, what)]


def parse_time(value: Any, what: str) -> int:
    """RFC 3339 UTC with whole seconds to Unix seconds."""
    if not (isinstance(value, str) and TIME.match(value)):
        raise Refused("bad_message", what)
    try:
        return int(timefmt.parse_time(value).timestamp())
    except (FormatError, ValueError) as exc:
        raise Refused("bad_message", what) from exc


def fmt_time(unix: int) -> str:
    return timefmt.iso_seconds(unix)


def day_of(unix: int) -> int:
    return unix // DAY


def pad(body: bytes, size: int) -> bytes:
    """`u32(len(body)) || body || zero bytes`, exactly `size` bytes."""
    need(len(body) + 4 <= size, "too_large")
    return u32(len(body)) + body + bytes(size - 4 - len(body))


def unpad(padded: bytes) -> bytes:
    n = int.from_bytes(padded[:4], "big")
    need(n + 4 <= len(padded), "bad_envelope", "length")
    need(not any(padded[4 + n :]), "bad_envelope", "padding")
    return padded[4 : 4 + n]


def body_of(doc: JsonObject) -> bytes:
    return canonical_json({k: v for k, v in doc.items() if k != "signature"})


def sign(doc: JsonObject, tag: str, key: SigningKey) -> JsonObject:
    out = {k: v for k, v in doc.items() if k != "signature"}
    out["signature"] = key.sign(tag, canonical_json(out)).hex()
    return out


def sig_ok(doc: JsonObject, tag: str, public_hex: str) -> bool:
    try:
        sig = bytes.fromhex(doc["signature"])
        return verify(bytes.fromhex(public_hex), tag, body_of(doc), sig)
    except (KeyError, ValueError, TypeError):
        return False
