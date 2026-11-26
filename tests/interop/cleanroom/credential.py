"""Member credentials (network.md 5, 6.1, 6.2, 6.5) and the pack's log
proof (pack.md 5). The node side (issue) and the verifier side (check)."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

import biscuit_auth as bisc

from .core import Refused, Signer, cjson, fmt_time, is_hex, parse_time, tagged_hash, verify_doc
from .logs import leaf_hash, verify_inclusion

MAX_LIFE = 86_400
FORMAT = "biscuit-v3"


@dataclass(frozen=True)
class Facts:
    network: str
    node: str
    subject: str
    kind: str
    pid: str | None
    email_tags: tuple[str, ...]
    control_head: int
    issued: int
    expires: int

    def source(self) -> str:
        """The block source of 6.1, in its fixed order."""
        lines = [
            'anagram("member_credential", 1);',
            f'network("{self.network}");',
            f'node("{self.node}");',
            f"subject(hex:{self.subject});",
            f'kind("{self.kind}");',
        ]
        if self.pid is not None:
            lines.append(f'pid("{self.pid}");')
        lines += [f"email_tag(hex:{t});" for t in sorted(self.email_tags)]
        lines += [
            f"control_head({self.control_head});",
            f"issued({fmt_time(self.issued)});",
            f"expires({fmt_time(self.expires)});",
            f"check if time($t), $t < {fmt_time(self.expires)};",
        ]
        return "\n".join(lines) + "\n"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _private(node: Signer) -> bisc.PrivateKey:
    return bisc.PrivateKey.from_bytes(node.seed, bisc.Algorithm.Ed25519)


def issue(facts: Facts, node: Signer) -> bytes:
    """Node side: one authority block with the facts and the check."""
    builder = bisc.BiscuitBuilder(facts.source())
    token = builder.build(_private(node))
    return unb64url(token.to_base64())


def credential_hash(raw: bytes) -> str:
    return tagged_hash("anagram/v1/net/member-credential", raw).hex()


def member_commit(subject: str, salt: str) -> str:
    """network.md 6.5: the join commitment of a new member."""
    return tagged_hash("anagram/v1/net/member-join", bytes.fromhex(subject + salt)).hex()


def log_entry(facts: Facts, raw: bytes, node: Signer, member: str | None = None) -> dict:
    entry = {
        "credential_hash": credential_hash(raw),
        "expires": fmt_time(facts.expires),
        "kind": "member_credential",
        "member": member,
        "node_id": facts.node,
        "schema": "anagram.enclave.member_credential.v1",
        "signer": node.hex,
    }
    return node.sign_doc("anagram/v1/enclave/sign/member-credential", entry)


# ---- verification (6.2) ----------------------------------------------------------

_FACT = re.compile(r"^([a-z_]+)\((.*)\);$")


def _read(source: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in source.strip("\n").split("\n"):
        if line.startswith("check if"):
            out.setdefault("__check", []).append(line)
            continue
        m = _FACT.match(line)
        if not m:
            raise Refused("bad_credential", f"not a fact: {line}")
        out.setdefault(m.group(1), []).append(m.group(2))
    return out


def _one(f: dict[str, list[str]], name: str) -> str:
    v = f.get(name, [])
    if len(v) != 1:
        raise Refused("bad_credential", f"count of {name}")
    return v[0]


def _str(v: str) -> str:
    if not (v.startswith('"') and v.endswith('"')):
        raise Refused("bad_credential", "not a string")
    return v[1:-1]


def _facts(source: str) -> Facts:
    f = _read(source)
    if _one(f, "anagram") != '"member_credential", 1':
        raise Refused("bad_credential", "marker")
    kind = _str(_one(f, "kind"))
    subject = _one(f, "subject")
    if not subject.startswith("hex:") or not is_hex(subject[4:], 32):
        raise Refused("bad_credential", "subject")
    pid = _str(_one(f, "pid")) if kind == "person" else None
    if kind == "group" and "pid" in f:
        raise Refused("bad_credential", "pid in group")
    tags = tuple(t.removeprefix("hex:") for t in f.get("email_tag", []))
    if len(tags) > (3 if kind == "person" else 0) or kind not in ("person", "group"):
        raise Refused("bad_credential", "email tags")
    try:
        issued = parse_time(_one(f, "issued"))
        expires = parse_time(_one(f, "expires"))
        head = int(_one(f, "control_head"))
    except ValueError as e:
        raise Refused("bad_credential", "types") from e
    return Facts(
        _str(_one(f, "network")), _str(_one(f, "node")), subject[4:], kind, pid, tags, head,
        issued, expires,
    )  # fmt: skip


def verify_credential(
    cred: dict,
    *,
    node_keys: dict[str, str],
    network: str,
    subject: str,
    kind: str,
    now: int,
    log_roots: dict[int, bytes],
) -> Facts:
    """Steps 1 to 8 of network.md 6.2 and the log proof of pack.md 5. Step 9
    (control chains) needs the roster state, which a client does not keep.
    """
    if not isinstance(cred, dict) or set(cred) != {"format", "log", "token"}:
        raise Refused("bad_credential", "fields")
    if cred["format"] != FORMAT:
        raise Refused("bad_credential", "format")
    try:
        unverified = bisc.UnverifiedBiscuit.from_base64(cred["token"])
        f0 = _facts(unverified.block_source(0))
    except Refused:
        raise
    except Exception as e:  # the library raises its own error types
        raise Refused("bad_credential", "decode") from e
    if f0.node not in node_keys:
        raise Refused("bad_credential", "node not in roster")
    root = bisc.PublicKey.from_bytes(bytes.fromhex(node_keys[f0.node]), bisc.Algorithm.Ed25519)
    try:
        token = bisc.Biscuit.from_base64(cred["token"], root)
    except Exception as e:
        raise Refused("bad_credential", "signature") from e
    if token.block_count() != 1:
        raise Refused("bad_credential", "blocks")
    source = token.block_source(0)
    facts = _facts(source)
    if not 0 < facts.expires - facts.issued <= MAX_LIFE:
        raise Refused("bad_credential", "life")
    if source != facts.source():
        raise Refused("bad_credential", "block is not exactly the facts and the check")
    if facts.issued > now + 300:
        raise Refused("bad_credential", "issued in the future")
    _authorise(token, now)
    if not (now < facts.expires and facts.issued >= now - MAX_LIFE):
        raise Refused("expired")
    if facts.network != network or facts.subject != subject or facts.kind != kind:
        raise Refused("bad_credential", "network, subject or kind")
    _check_log(cred, facts, unb64url(cred["token"]), node_keys[f0.node], log_roots)
    return facts


def _authorise(token: bisc.Biscuit, now: int) -> None:
    b = bisc.AuthorizerBuilder(f"time({fmt_time(now)}); allow if true;")
    try:
        b.build(token).authorize()
    except Exception as e:
        raise Refused("expired") from e


def join_ranks(entries: list[dict]) -> dict[int, tuple[str, str, int]]:
    """network.md 6.7: for each join entry (a `member_credential` entry
    with `member` not null), by log index: its node, its month (UTC
    `YYYY-MM` of `expires`) and its rank in log order among the join
    entries of that node and month. Renewals do not count."""
    seen: dict[tuple[str, str], int] = {}
    out = {}
    for index, e in enumerate(entries):
        if e.get("kind") != "member_credential" or e["member"] is None:
            continue
        key = (e["node_id"], e["expires"][:7])
        seen[key] = seen.get(key, 0) + 1
        out[index] = (*key, seen[key])
    return out


def check_join(
    entries: list[dict], at: int, node: str, subject: str, salt: str, limit: int
) -> None:
    """network.md 6.2 step 8a: the join entry that a credential names."""
    ranks = join_ranks(entries)
    if at not in ranks:
        raise Refused("bad_credential", "not a join entry")
    e = entries[at]
    if e["node_id"] != node or e["member"] != member_commit(subject, salt):
        raise Refused("bad_credential", "join entry")
    if ranks[at][2] > limit:
        raise Refused("issuance_limit")


def _check_log(cred: dict, facts: Facts, raw: bytes, node_key: str, roots: dict) -> None:
    log = cred["log"]
    names = {"entry_signature", "hashes", "index", "join", "tree_size"}
    if not isinstance(log, dict) or set(log) != names:
        raise Refused("bad_credential", "log")
    join = log["join"]
    if not isinstance(join, dict) or set(join) != {"index", "salt"} or not is_hex(join["salt"], 16):
        raise Refused("bad_credential", "join")
    if not (isinstance(join["index"], int) and 0 <= join["index"] <= log["index"]):
        raise Refused("bad_credential", "join index")
    first = join["index"] == log["index"]
    entry = {
        "credential_hash": credential_hash(raw),
        "expires": fmt_time(facts.expires),
        "kind": "member_credential",
        "member": member_commit(facts.subject, join["salt"]) if first else None,
        "node_id": facts.node,
        "schema": "anagram.enclave.member_credential.v1",
        "signature": log["entry_signature"],
        "signer": node_key,
    }
    if not verify_doc(node_key, "anagram/v1/enclave/sign/member-credential", entry):
        raise Refused("bad_credential", "entry signature")
    size, index, hashes = log["tree_size"], log["index"], log["hashes"]
    if not (1 <= size <= 2**53 - 1 and 0 <= index < size and len(hashes) <= 32):
        raise Refused("bad_credential", "proof form")
    if not all(is_hex(h, 32) for h in hashes) or size not in roots:
        raise Refused("bad_credential", "no trusted root")
    path = [bytes.fromhex(h) for h in hashes]
    if not verify_inclusion(leaf_hash(cjson(entry)), index, size, path, roots[size]):
        raise Refused("bad_credential", "inclusion")
