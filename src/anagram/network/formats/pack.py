"""`anagram.pack.v1` and `anagram.known.v1` (spec/pack.md)."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from anagram.core.canonical import CanonicalError, JsonObject, canonical_json, loads_canonical
from anagram.core.crypto.hashing import tagged_hash, u32, u64
from anagram.core.crypto.signing import SigningKey, verify
from anagram.core.signed import b64url
from anagram.network.formats import credential as cred
from anagram.network.formats.strict import (
    DAY,
    DOMAIN,
    HEX32,
    ID,
    MAX_SAFE,
    MAX_U32,
    NODE_ID,
    ROR,
    Refused,
    check_x25519_public,
    concepts,
    enum,
    exact,
    hexval,
    intval,
    need,
    parse_time,
    sig_ok,
    sign,
    sorted_unique,
    text,
)

SCHEMA = "anagram.pack.v1"
KNOWN_SCHEMA = b"anagram.known.v1"
TAG_SIGN = "anagram/v1/pack/sign"
TAG_KNOWN_SIGN = "anagram/v1/known/sign"
TAG_KNOWN = b"anagram/v1/known"
TAG_KNOWN_DAY = "anagram/v1/known/day"
PACK_MAX = 49_152
KNOWN_MAX_ENTRIES = 5_000
KNOWN_ENTRY = 64
KNOWN_HEADER = 100
KNOWN_EMPTY = 0xFFFFFFFF
MAX_LIFE = 30 * DAY
MAX_AGE = 2 * DAY
CLOCK_SKEW = 300
WEEKLY_CAP_MAX = 10  # 3.3: the person's weekly cap; the enclave applies min(it, weekly_cap_max)
WEEKLY_CAP_DEFAULT = 3  # C43: the app's default

TYPES = (
    "co_supervision",
    "data_material_share",
    "instrument_access",
    "method_help",
    "replication",
    "research_fit",
)
GROUP_TYPES = ("co_supervision", "data_material_share", "instrument_access")
CLASSES = (
    "data",
    "instrument",
    "material",
    "method",
    "problem",
    "replication",
    "skill",
    "supervision",
)
SCOPES = ("both", "inside", "outside")
RULES = ("any", "inside", "outside")
READING_KINDS = (
    "asks",
    "negative_result",
    "offers",
    "stage",
    "stuck_on",
    "tacit_skill",
    "trajectory",
)
CONFIDENCE = ("high", "low", "med")
YES_NO = ("no", "yes")
# kind -> (argument type, value type). Argument: "concept" (integer), None, or
# an enum tuple. Value: an enum tuple or an inclusive integer range.
FACTS: dict[str, tuple[Any, Any]] = {
    "access_mode": (("remote", "send_samples", "visit"), YES_NO),
    "capacity_months": (None, range(0, 61)),
    "capacity_students": (None, range(0, 21)),
    "has_data": ("concept", ("large", "medium", "small")),
    "has_instrument": ("concept", YES_NO),
    "has_material": ("concept", YES_NO),
    "has_method": ("concept", YES_NO),
    "has_used": ("concept", YES_NO),
    "lead_time_weeks": (None, range(0, 105)),
    "open_to": (
        ("access", "advice", "co_supervise", "collab", "replication", "share"),
        ("no", "not_now", "yes"),
    ),
    "solved": ("concept", YES_NO),
    "stage": (None, ("early", "idea", "mature", "ongoing")),
    "supervises_in": ("concept", YES_NO),
    "terms": (None, ("agreement", "none", "open")),
    "timeline_months": (None, range(0, 61)),
    "uses_method": ("concept", YES_NO),
}


@dataclass(frozen=True)
class Limits:
    lines: int  # offers, and wants, each
    readings: int
    budgets: dict[str, int]


_COMMON = {
    "block": 6_144,
    "charter": 1_024,
    "credential": 3_584,
    "deny": 1_536,
    "facts": 9_216,
    "teasers": 512,
    "topics": 1_024,
}
LIMITS = {
    "person": Limits(10, 40, {**_COMMON, "lines": 8_192, "readings": 11_264}),
    "group": Limits(20, 20, {**_COMMON, "lines": 16_384, "readings": 5_632}),
}
FIELDS = {
    "block",
    "charter",
    "consent",
    "created",
    "credential",
    "deny",
    "expires",
    "facts",
    "kind",
    "lines",
    "readings",
    "reply_key",
    "schema",
    "signature",
    "subject",
    "teasers",
    "topics",
    "version",
    "vocab",
}
LINE_ID = {
    "offers": re.compile(r"^o(0[1-9]|1[0-9]|20)$"),
    "wants": re.compile(r"^w(0[1-9]|1[0-9]|20)$"),
}


@dataclass
class Context:
    """What the enclave knows when it checks a pack (spec/pack.md section 7)."""

    now: int
    network: str
    node_keys: dict[str, str]  # node ID -> node key hex (roster)
    log_roots: Mapping[int, bytes]  # tree size -> trusted root (enclave-trust.md)
    descriptor_set: str
    statement: str  # hex SHA-256 of the consent statement
    formats: tuple[str, ...] = (cred.FORMAT_BISCUIT,)
    teasers_allowed: bool = False
    schemas: tuple[str, ...] = (SCHEMA,)


def size_of(value: Any) -> int:
    return len(canonical_json(value))


def _budget(doc: JsonObject, name: str, limits: Limits) -> None:
    need(size_of(doc[name]) <= limits.budgets[name], "too_large", name)


def _line(obj: Any, list_name: str, kind: str) -> str:
    exact(obj, {"class", "concepts", "id", "scope", "text", "types"}, "line")
    enum(obj["class"], CLASSES, "line class")
    concepts(obj["concepts"], 8, "line concepts")
    enum(obj["scope"], SCOPES, "line scope")
    text(obj["text"], 140, "line text")
    types = sorted_unique(obj["types"], 6, "line types")
    need(len(types) >= 1, "bad_message", "line types")
    for t in types:
        enum(t, GROUP_TYPES if kind == "group" else TYPES, "line type")
    return hexval(obj["id"], LINE_ID[list_name], "line id")


def _lines(doc: JsonObject, limits: Limits) -> set[str]:
    lines = exact(doc["lines"], {"offers", "wants"}, "lines")
    ids: set[str] = set()
    for name in ("offers", "wants"):
        items = lines[name]
        need(isinstance(items, list) and len(items) <= limits.lines, "bad_message", name)
        got = [_line(x, name, doc["kind"]) for x in items]
        need(got == sorted(set(got)), "bad_message", f"{name}: id order")
        ids |= set(got)
    need(len(ids) >= 1, "bad_message", "a pack has at least one line")
    return ids


def _readings(doc: JsonObject, limits: Limits) -> None:
    items = doc["readings"]
    need(isinstance(items, list) and len(items) <= limits.readings, "bad_message", "readings")
    for r in items:
        exact(r, {"concepts", "confidence", "kind", "text"}, "reading")
        concepts(r["concepts"], 8, "reading concepts")
        enum(r["confidence"], CONFIDENCE, "confidence")
        enum(r["kind"], READING_KINDS, "reading kind")
        text(r["text"], 200, "reading text")


def _fact(f: Any) -> tuple[str, int, int, str]:
    """The sort key of a fact (kind, then arg)."""
    exact(f, {"arg", "kind", "value"}, "fact")
    kind = enum(f["kind"], tuple(FACTS), "fact kind")
    arg_type, value_type = FACTS[kind]
    if arg_type == "concept":
        intval(f["arg"], 0, MAX_U32, "fact arg")
    elif arg_type is None:
        need(f["arg"] is None, "bad_message", "fact arg")
    else:
        enum(f["arg"], arg_type, "fact arg")
    if isinstance(value_type, range):
        intval(f["value"], value_type.start, value_type.stop - 1, "fact value")
    else:
        enum(f["value"], value_type, "fact value")
    arg = f["arg"]
    return (kind, -1 if arg is None else 0, arg if isinstance(arg, int) else 0, str(arg))


def _facts(doc: JsonObject) -> None:
    items = doc["facts"]
    need(isinstance(items, list) and len(items) <= 150, "bad_message", "facts")
    keys = [_fact(f) for f in items]
    need(keys == sorted(set(keys)), "bad_message", "fact order")


def _charter(doc: JsonObject) -> None:
    c = exact(doc["charter"], {"disclosure", "protocols", "rules", "weekly_cap"}, "charter")
    enum(c["disclosure"], ("d0",), "disclosure")
    allowed = GROUP_TYPES if doc["kind"] == "group" else TYPES
    protocols = sorted_unique(c["protocols"], len(allowed), "protocols")
    need(len(protocols) >= 1, "bad_message", "protocols")
    for p in protocols:
        enum(p, allowed, "protocol")
    rules = c["rules"]
    need(isinstance(rules, dict) and set(rules) == set(protocols), "bad_message", "rules")
    for r in rules.values():
        enum(r, RULES, "rule")
    intval(c["weekly_cap"], 1, WEEKLY_CAP_MAX, "weekly_cap")


def _deny(doc: JsonObject) -> None:
    d = exact(doc["deny"], {"domains", "nodes", "rors"}, "deny")
    patterns = {"domains": DOMAIN, "nodes": NODE_ID, "rors": ROR}
    total = 0
    for name, pattern in patterns.items():
        for v in sorted_unique(d[name], 32, f"deny {name}"):
            hexval(v, pattern, f"deny {name}")
        total += len(d[name])
    need(total <= 32, "bad_message", "deny: at most 32 entries")


SUBJECT_REF = re.compile(r"^(person:[0-9a-f]{64}|pid:[0-9a-f]{32})$")


def _block(doc: JsonObject, line_ids: set[str]) -> None:
    b = exact(doc["block"], {"hide", "people"}, "block")
    for v in sorted_unique(b["people"], 128, "block people"):
        hexval(v, SUBJECT_REF, "block people")
    hide = b["hide"]
    need(isinstance(hide, list), "bad_message", "hide")
    keys = []
    for h in hide:
        exact(h, {"from", "line"}, "hide")
        hexval(h["from"], SUBJECT_REF, "hide from")
        need(h["line"] in line_ids, "bad_message", "hide line")
        keys.append((h["from"], h["line"]))
    need(keys == sorted(set(keys)), "bad_message", "hide order")
    need(len(b["people"]) + len(hide) <= 128, "bad_message", "block: at most 128 entries")


def _header(doc: JsonObject, ctx: Context) -> None:
    enum(doc["kind"], ("group", "person"), "kind")
    hexval(doc["subject"], HEX32, "subject")
    check_x25519_public(
        bytes.fromhex(hexval(doc["reply_key"], HEX32, "reply_key")), "bad_message", "reply_key"
    )
    intval(doc["version"], 1, MAX_SAFE, "version")
    hexval(doc["vocab"], ID, "vocab")
    c = exact(doc["consent"], {"approved_at", "descriptor_set", "statement"}, "consent")
    parse_time(c["approved_at"], "approved_at")
    hexval(c["descriptor_set"], HEX32, "descriptor_set")
    hexval(c["statement"], HEX32, "statement")
    created = parse_time(doc["created"], "created")
    expires = parse_time(doc["expires"], "expires")
    need(created < expires <= created + MAX_LIFE, "bad_message", "expires")
    need(parse_time(c["approved_at"], "approved_at") <= created, "bad_message", "approved_at")
    check_age(created, ctx.now)
    need(c["descriptor_set"] == ctx.descriptor_set, "bad_message", "consent descriptor set")
    need(c["statement"] == ctx.statement, "bad_message", "consent statement")


def check_age(created: int, now: int) -> None:
    """At most 5 minutes after the enclave time, at most 48 hours before it
    (section 8). Packs, covers and known objects share the rule."""
    need(created <= now + CLOCK_SKEW, "bad_message", "created in the future")
    need(now - created <= MAX_AGE, "expired", "older than 48 h")


def check_credential(doc: JsonObject, ctx: Context) -> cred.MemberFacts:
    c = doc["credential"]
    need(isinstance(c, dict) and set(c) <= {"format", "log", "token"}, "bad_message", "credential")
    need("log" in c, "bad_credential", "no log proof")
    exact(c, {"format", "log", "token"}, "credential")
    need(c["format"] in ctx.formats, "bad_credential", "format")
    raw = cred.unb64url(c["token"])
    facts = _read_credential(c["format"], raw, ctx)
    need(facts.network == ctx.network, "bad_credential", "network")
    need(facts.subject == doc["subject"], "bad_credential", "subject")
    need(facts.kind == doc["kind"], "bad_credential", "kind")
    need(facts.issued <= ctx.now + CLOCK_SKEW, "bad_credential", "issued in the future")
    cred.check_log_proof(c["log"], facts, raw, ctx.node_keys[facts.node], ctx.log_roots)
    return facts


def _read_credential(fmt: str, raw: bytes, ctx: Context) -> cred.MemberFacts:
    node = _peek_node(fmt, raw)
    key = ctx.node_keys.get(node)
    if key is None:
        raise Refused("bad_credential", "node not in the roster")
    if fmt == cred.FORMAT_BISCUIT:
        return cred.read_member_biscuit(raw, key, ctx.now)
    return cred.read_member_json(raw, key, ctx.now)


def _peek_node(fmt: str, raw: bytes) -> str:
    """The node named by a credential, read before the signature check."""
    if fmt == cred.FORMAT_JSON:
        try:
            node = loads_canonical(raw).get("node")
        except (CanonicalError, ValueError, AttributeError) as exc:
            raise Refused("bad_credential", "json") from exc
        if not isinstance(node, str):
            raise Refused("bad_credential", "node")
        return node
    import biscuit_auth as ba

    try:
        token = ba.UnverifiedBiscuit.from_base64(b64url(raw))
        found = re.findall(r'^node\("(node-[0-9a-f]{32})"\);$', token.block_source(0), re.M)
    except Exception as exc:  # the library raises several classes
        raise Refused("bad_credential", "biscuit") from exc
    need(len(found) == 1, "bad_credential", "node")
    node_id: str = found[0]  # a group of the pattern
    return node_id


def check_pack_bytes(body: bytes, ctx: Context) -> tuple[JsonObject, cred.MemberFacts]:
    """All stateless checks of spec/pack.md section 7, in order."""
    need(len(body) <= PACK_MAX, "too_large", "pack")
    try:
        doc = loads_canonical(body)
    except (CanonicalError, ValueError) as exc:
        raise Refused("bad_message", "not canonical JSON") from exc
    need(isinstance(doc, dict), "bad_message", "object")
    need(doc.get("schema") in ctx.schemas, "unsupported_schema", str(doc.get("schema")))
    exact(doc, FIELDS, "pack")
    _header(doc, ctx)
    limits = LIMITS[doc["kind"]]
    line_ids = _lines(doc, limits)
    _readings(doc, limits)
    _facts(doc)
    _charter(doc)
    concepts(doc["topics"], 64, "topics")
    _deny(doc)
    _block(doc, line_ids)
    teasers = doc["teasers"]
    need(isinstance(teasers, list) and len(teasers) <= 3, "bad_message", "teasers")
    for t in teasers:
        text(t, 100, "teaser")
    need(ctx.teasers_allowed or not teasers, "bad_message", "teasers not allowed (E1 a)")
    for name in limits.budgets:
        _budget(doc, name, limits)
    need(sig_ok(doc, TAG_SIGN, doc["subject"]), "bad_signature", "pack")
    facts = check_credential(doc, ctx)
    return doc, facts


def sign_pack(doc: JsonObject, key: SigningKey) -> JsonObject:
    return sign(doc, TAG_SIGN, key)


# The known object (binary).


def normalise_email(address: str) -> str:
    a = address.strip(" \t\r\n")
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in a)


def known_tag(identifier: str) -> bytes:
    """HMAC-SHA256 with the public key `anagram/v1/known` (spec/pack.md section 9.2)."""
    return hmac.new(TAG_KNOWN, identifier.encode("utf-8"), hashlib.sha256).digest()


def known_weekday(subject: bytes) -> int:
    """The weekday index (day number mod 7) of the weekly known upload."""
    return tagged_hash(TAG_KNOWN_DAY, subject)[0] % 7


def person_id(subject_hex: str) -> str:
    return f"person:{subject_hex}"


def email_id(address: str) -> str:
    return f"email:{normalise_email(address)}"


def encode_known(
    subject: SigningKey,
    version: int,
    created: int,
    vocab: str,
    entries: Sequence[tuple[bytes, list[int]]],
) -> bytes:
    need(len(entries) <= KNOWN_MAX_ENTRIES, "too_large", "known entries")
    rows = sorted(entries, key=lambda e: e[0])
    need(len({t for t, _ in rows}) == len(rows), "bad_message", "duplicate tag")
    vocab_raw = vocab.encode("ascii")
    out = bytearray(KNOWN_SCHEMA + subject.public_bytes() + u64(version) + u64(created))
    out += vocab_raw + bytes(32 - len(vocab_raw)) + u32(len(rows))
    for tag, cs in rows:
        need(len(tag) == 32 and len(cs) <= 8 and cs == sorted(set(cs)), "bad_message", "entry")
        out += tag + b"".join(u32(c) for c in cs) + u32(KNOWN_EMPTY) * (8 - len(cs))
    out += subject.sign(TAG_KNOWN_SIGN, bytes(out))
    return bytes(out)


@dataclass(frozen=True)
class Known:
    subject: str
    version: int
    created: int
    vocab: str
    entries: list[tuple[str, list[int]]]


def _entry(raw: bytes) -> tuple[str, list[int]]:
    cs = [int.from_bytes(raw[32 + 4 * i : 36 + 4 * i], "big") for i in range(8)]
    used = [c for c in cs if c != KNOWN_EMPTY]
    need(cs == used + [KNOWN_EMPTY] * (8 - len(used)), "bad_message", "empty slots last")
    need(used == sorted(set(used)), "bad_message", "concept order")
    return raw[:32].hex(), used


def decode_known(body: bytes) -> Known:
    need(len(body) >= KNOWN_HEADER + 64 and body[:16] == KNOWN_SCHEMA, "bad_message", "known")
    count = int.from_bytes(body[96:100], "big")
    need(count <= KNOWN_MAX_ENTRIES, "too_large", "known entries")
    need(len(body) == KNOWN_HEADER + KNOWN_ENTRY * count + 64, "bad_message", "known length")
    vocab_raw = body[64:96].rstrip(b"\0")
    need(
        b"\0" not in vocab_raw and bool(ID.match(vocab_raw.decode("latin-1"))),
        "bad_message",
        "vocab",
    )
    subject = body[16:48]
    signed, sig = body[:-64], body[-64:]
    need(verify(subject, TAG_KNOWN_SIGN, signed, sig), "bad_signature", "known")
    entries = [
        _entry(body[KNOWN_HEADER + KNOWN_ENTRY * i : KNOWN_HEADER + KNOWN_ENTRY * (i + 1)])
        for i in range(count)
    ]
    tags = [t for t, _ in entries]
    need(tags == sorted(set(tags)), "bad_message", "tag order")
    return Known(
        subject=subject.hex(),
        version=int.from_bytes(body[48:56], "big"),
        created=int.from_bytes(body[56:64], "big"),
        vocab=vocab_raw.decode("ascii"),
        entries=entries,
    )
