"""The pack (pack.md 3 to 8) and the known object (pack.md 9)."""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field

from .core import (
    Refused,
    Signer,
    cjson,
    fmt_time,
    is_hex,
    is_text,
    parse_canonical,
    parse_time,
    sha256,
    tagged_hash,
    u32,
    u64,
    verify,
    verify_doc,
)
from .credential import verify_credential

PACK = "anagram.pack.v1"
PACK_MAX = 49_152
FIELDS = {
    "block", "charter", "consent", "created", "credential", "deny", "expires", "facts",
    "kind", "lines", "readings", "reply_key", "schema", "signature", "subject", "teasers",
    "topics", "version", "vocab",
}  # fmt: skip
TYPES = (
    "co_supervision", "data_material_share", "instrument_access", "method_help",
    "replication", "research_fit",
)  # fmt: skip
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
READING_KINDS = (
    "asks",
    "negative_result",
    "offers",
    "stage",
    "stuck_on",
    "tacit_skill",
    "trajectory",
)
BUDGETS = {
    "person": {"credential": 3584, "charter": 1024, "lines": 8192, "teasers": 512,
               "readings": 11264, "facts": 9216, "topics": 1024, "deny": 1536, "block": 6144},
    "group": {"credential": 3584, "charter": 1024, "lines": 16384, "teasers": 512,
              "readings": 5632, "facts": 9216, "topics": 1024, "deny": 1536, "block": 6144},
}  # fmt: skip
LIMITS = {"person": {"lines": 10, "readings": 40}, "group": {"lines": 20, "readings": 20}}
YES_NO = ("yes", "no")
FACT_RULES: dict[str, tuple[object, tuple]] = {
    "has_method": ("concept", YES_NO),
    "has_used": ("concept", YES_NO),
    "solved": ("concept", YES_NO),
    "has_instrument": ("concept", YES_NO),
    "has_material": ("concept", YES_NO),
    "has_data": ("concept", ("small", "medium", "large")),
    "uses_method": ("concept", YES_NO),
    "supervises_in": ("concept", YES_NO),
    "access_mode": (("visit", "send_samples", "remote"), YES_NO),
    "open_to": (
        ("collab", "advice", "access", "share", "replication", "co_supervise"),
        ("yes", "no", "not_now"),
    ),
    "stage": (None, ("idea", "early", "ongoing", "mature")),
    "terms": (None, ("open", "agreement", "none")),
    "timeline_months": (None, (0, 60)),
    "lead_time_weeks": (None, (0, 104)),
    "capacity_months": (None, (0, 60)),
    "capacity_students": (None, (0, 20)),
}
VOCAB = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,31}$")
ROR = re.compile(r"^0[a-z0-9]{6}[0-9]{2}$")
NODE = re.compile(r"^node-[0-9a-f]{32}$")
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
TLD = re.compile(r"^[a-z]{2,63}$")
REF = re.compile(r"^(person:[0-9a-f]{64}|pid:[0-9a-f]{32})$")


def sign_pack(doc: dict, subject: Signer) -> dict:
    return subject.sign_doc("anagram/v1/pack/sign", doc)


@dataclass
class Context:
    """What a receiver needs to check a pack (pack.md 14 'context')."""

    now: int
    descriptor_set: str
    statement: str
    network: str
    node_keys: dict[str, str]
    log_roots: dict[int, bytes]
    schemas: tuple[str, ...] = (PACK,)
    teasers_allowed: bool = False
    extra: dict = field(default_factory=dict)


def _sorted_unique(xs: list) -> bool:
    return all(a < b for a, b in zip(xs, xs[1:], strict=False))


def _concepts(xs: object, n: int) -> bool:
    return (
        isinstance(xs, list)
        and len(xs) <= n
        and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 2**32 for x in xs)
        and _sorted_unique(xs)
    )


def _types(xs: object, kind: str) -> bool:
    allowed = GROUP_TYPES if kind == "group" else TYPES
    return (
        isinstance(xs, list)
        and 1 <= len(xs) <= 6
        and all(x in allowed for x in xs)
        and _sorted_unique(xs)
    )


def _header(d: dict, ctx: Context) -> None:
    bad = Refused("bad_message", "header")
    if d["kind"] not in ("person", "group") or not is_hex(d["subject"], 32):
        raise bad
    v = d["version"]
    if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 2**53 - 1:
        raise bad
    try:
        created, expires = parse_time(d["created"]), parse_time(d["expires"])
        consent = d["consent"]
        approved = parse_time(consent["approved_at"])
    except (ValueError, TypeError, KeyError) as e:
        raise Refused("bad_message", "times") from e
    if not created < expires <= created + 30 * 86_400:
        raise bad
    if not isinstance(d["vocab"], str) or not VOCAB.match(d["vocab"]):
        raise bad
    if set(consent) != {"approved_at", "descriptor_set", "statement"} or approved > created:
        raise Refused("bad_message", "consent")
    if consent["descriptor_set"] != ctx.descriptor_set or consent["statement"] != ctx.statement:
        raise Refused("bad_message", "consent values")
    if not is_hex(d["reply_key"], 32) or not is_hex(d["signature"], 64):
        raise bad
    if created > ctx.now + 300:
        raise Refused("bad_message", "created in the future")
    if created < ctx.now - 48 * 3_600:
        raise Refused("expired", "older than 48 hours")


def _charter(c: object, kind: str) -> bool:
    if not isinstance(c, dict) or set(c) != {"disclosure", "protocols", "rules", "weekly_cap"}:
        return False
    if c["disclosure"] != "d0" or not _types(c["protocols"], kind):
        return False
    if not isinstance(c["rules"], dict) or set(c["rules"]) != set(c["protocols"]):
        return False
    if not all(r in ("any", "inside", "outside") for r in c["rules"].values()):
        return False
    return isinstance(c["weekly_cap"], int) and 1 <= c["weekly_cap"] <= 10


def _lines(ls: object, kind: str) -> bool:
    if not isinstance(ls, dict) or set(ls) != {"offers", "wants"}:
        return False
    n = LIMITS[kind]["lines"]
    total = 0
    for side, prefix in (("offers", "o"), ("wants", "w")):
        items = ls[side]
        if not isinstance(items, list) or len(items) > n:
            return False
        ids = []
        for x in items:
            if not isinstance(x, dict) or set(x) != {
                "class",
                "concepts",
                "id",
                "scope",
                "text",
                "types",
            }:
                return False
            if not re.fullmatch(prefix + r"(0[1-9]|1[0-9]|20)", str(x["id"])):
                return False
            if x["class"] not in CLASSES or x["scope"] not in ("inside", "outside", "both"):
                return False
            if (
                not _concepts(x["concepts"], 8)
                or not is_text(x["text"], 140)
                or not _types(x["types"], kind)
            ):
                return False
            ids.append(x["id"])
        if not _sorted_unique(ids):
            return False
        total += len(items)
    return total >= 1


def _readings(rs: object, kind: str) -> bool:
    if not isinstance(rs, list) or len(rs) > LIMITS[kind]["readings"]:
        return False
    for r in rs:
        if not isinstance(r, dict) or set(r) != {"concepts", "confidence", "kind", "text"}:
            return False
        if r["kind"] not in READING_KINDS or r["confidence"] not in ("low", "med", "high"):
            return False
        if not _concepts(r["concepts"], 8) or not is_text(r["text"], 200):
            return False
    return True


def _fact_key(f: dict) -> tuple:
    a = f["arg"]
    rank = 0 if a is None else (1 if isinstance(a, int) else 2)
    return (f["kind"], rank, a if a is not None else 0)


def _facts(fs: object) -> bool:
    if not isinstance(fs, list) or len(fs) > 150:
        return False
    for f in fs:
        if (
            not isinstance(f, dict)
            or set(f) != {"arg", "kind", "value"}
            or f["kind"] not in FACT_RULES
        ):
            return False
        arg_rule, values = FACT_RULES[f["kind"]]
        a, v = f["arg"], f["value"]
        if arg_rule == "concept":
            if not _concepts([a], 1):
                return False
        elif arg_rule is None:
            if a is not None:
                return False
        elif a not in arg_rule:
            return False
        if isinstance(values[0], int):
            lo, hi = values
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                return False
        elif v not in values:
            return False
    keys = [_fact_key(f) for f in fs]
    return _sorted_unique(keys)


def _domain(d: object) -> bool:
    if not isinstance(d, str) or not 1 <= len(d) <= 64:
        return False
    labels = d.split(".")
    return len(labels) >= 2 and all(LABEL.match(x) for x in labels) and bool(TLD.match(labels[-1]))


def _deny(dn: object) -> bool:
    if not isinstance(dn, dict) or set(dn) != {"domains", "nodes", "rors"}:
        return False
    ok = (
        all(isinstance(x, list) for x in dn.values())
        and all(_domain(x) for x in dn["domains"])
        and all(isinstance(x, str) and NODE.match(x) for x in dn["nodes"])
        and all(isinstance(x, str) and ROR.match(x) for x in dn["rors"])
    )
    return ok and all(_sorted_unique(x) for x in dn.values()) and sum(map(len, dn.values())) <= 32


def _block(b: object, lines: dict) -> bool:
    if not isinstance(b, dict) or set(b) != {"hide", "people"}:
        return False
    people, hide = b["people"], b["hide"]
    if not isinstance(people, list) or not all(isinstance(p, str) and REF.match(p) for p in people):
        return False
    ids = {x["id"] for side in lines.values() for x in side}
    if not isinstance(hide, list):
        return False
    for h in hide:
        if not isinstance(h, dict) or set(h) != {"from", "line"}:
            return False
        if not isinstance(h["from"], str) or not REF.match(h["from"]) or h["line"] not in ids:
            return False
    keys = [(h["from"], h["line"]) for h in hide]
    return _sorted_unique(people) and _sorted_unique(keys) and len(people) + len(hide) <= 128


def _fields(d: dict, ctx: Context) -> None:
    kind = d["kind"]
    teasers = d["teasers"]
    checks = [
        _charter(d["charter"], kind),
        _lines(d["lines"], kind),
        isinstance(teasers, list) and len(teasers) <= 3 and all(is_text(t, 100) for t in teasers),
        ctx.teasers_allowed or teasers == [],
        _readings(d["readings"], kind),
        _facts(d["facts"]),
        _concepts(d["topics"], 64),
        _deny(d["deny"]),
        _lines(d["lines"], kind) and _block(d["block"], d["lines"]),
    ]
    if not all(checks):
        raise Refused("bad_message", "field rule")


def field_size(v: object) -> int:
    return len(cjson(v))


def check_pack(raw: bytes, ctx: Context) -> dict:
    """pack.md 7.1 steps 1 to 9. Step 10 needs the enclave's state."""
    if len(raw) > PACK_MAX:
        raise Refused("too_large")
    try:
        d = parse_canonical(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise Refused("bad_message", "not canonical JSON") from e
    if not isinstance(d, dict):
        raise Refused("bad_message", "not an object")
    if d.get("schema") not in ctx.schemas:
        raise Refused("unsupported_schema")
    if set(d) != FIELDS:
        raise Refused("bad_message", "fields")
    _header(d, ctx)
    _fields(d, ctx)
    for name, limit in BUDGETS[d["kind"]].items():
        if field_size(d[name]) > limit:
            raise Refused("too_large", name)
    if not verify_doc(d["subject"], "anagram/v1/pack/sign", d):
        raise Refused("bad_signature")
    verify_credential(
        d["credential"],
        node_keys=ctx.node_keys,
        network=ctx.network,
        subject=d["subject"],
        kind=d["kind"],
        now=ctx.now,
        log_roots=ctx.log_roots,
    )
    return d


def build_pack(
    *,
    subject: Signer,
    reply_key: bytes,
    credential: dict,
    lines: dict,
    charter: dict,
    version: int,
    created: int,
    approved_at: int,
    descriptor_set: str,
    statement: str,
    vocab: str,
    deny: dict | None = None,
    block: dict | None = None,
    topics: list[int] | None = None,
) -> dict:
    doc = {
        "block": block or {"hide": [], "people": []},
        "charter": charter,
        "consent": {
            "approved_at": fmt_time(approved_at),
            "descriptor_set": descriptor_set,
            "statement": statement,
        },
        "created": fmt_time(created),
        "credential": credential,
        "deny": deny or {"domains": [], "nodes": [], "rors": []},
        "expires": fmt_time(created + 30 * 86_400),
        "facts": [],
        "kind": "person",
        "lines": lines,
        "readings": [],
        "reply_key": reply_key.hex(),
        "schema": PACK,
        "subject": subject.hex,
        "teasers": [],
        "topics": topics or [],
        "version": version,
        "vocab": vocab,
    }
    return sign_pack(doc, subject)


def statement_hash(text: str) -> str:
    return sha256(text.encode("utf-8")).hex()


# ---- known object (pack.md 9) -------------------------------------------------------

KNOWN = b"anagram.known.v1"
UNUSED = 0xFFFFFFFF


def known_tag(identifier: str) -> bytes:
    return hmac.new(b"anagram/v1/known", identifier.encode("utf-8"), hashlib.sha256).digest()


def email_identifier(address: str) -> str:
    a = address.strip(" \t\r\n")
    return "email:" + "".join(c.lower() if "A" <= c <= "Z" else c for c in a)


def known_weekday(subject_hex: str) -> int:
    return tagged_hash("anagram/v1/known/day", bytes.fromhex(subject_hex))[0] % 7


def build_known(
    subject: Signer, version: int, created: int, vocab: str, entries: list[tuple[bytes, list[int]]]
) -> bytes:
    body = KNOWN + subject.public + u64(version) + u64(created)
    body += vocab.encode("ascii").ljust(32, b"\x00") + u32(len(entries))
    for tag, concepts in sorted(entries):
        slots = sorted(concepts) + [UNUSED] * (8 - len(concepts))
        body += tag + b"".join(u32(c) for c in slots)
    return body + subject.sign("anagram/v1/known/sign", body)


def check_known(raw: bytes) -> dict:
    if len(raw) < 164 or raw[:16] != KNOWN:
        raise Refused("bad_message", "schema or length")
    count = struct.unpack(">I", raw[96:100])[0]
    if count > 5000:
        raise Refused("too_large")
    if len(raw) != 164 + 64 * count:
        raise Refused("bad_message", "length")
    vocab = raw[64:96].rstrip(b"\x00")
    if b"\x00" in vocab or not VOCAB.match(vocab.decode("ascii", "replace")):
        raise Refused("bad_message", "vocab")
    tags, prev = [], b""
    for i in range(count):
        e = raw[100 + 64 * i : 164 + 64 * i]
        tag, slots = e[:32], [struct.unpack(">I", e[32 + 4 * j : 36 + 4 * j])[0] for j in range(8)]
        used = [s for s in slots if s != UNUSED]
        if tag <= prev or slots[: len(used)] != used or not _sorted_unique(used):
            raise Refused("bad_message", "entries")
        prev = tag
        tags.append(tag)
    if not verify(raw[16:48], "anagram/v1/known/sign", raw[:-64], raw[-64:]):
        raise Refused("bad_signature")
    return {
        "subject": raw[16:48].hex(),
        "version": struct.unpack(">Q", raw[48:56])[0],
        "created": struct.unpack(">Q", raw[56:64])[0],
        "vocab": vocab.decode(),
        "count": count,
    }
