"""Member and node credentials (spec/network.md sections 5 to 7).

Format `biscuit-v3`: one Biscuit v3 authority block,
root key = the node key (member) or the roster key (node). The block must
hold exactly the facts and the one check of the spec: a verifier rebuilds
the source from the facts that it read and compares it with the block, so
an extra fact, rule or check is refused. Format
`anagram-json-v1` is the bespoke fallback of a member credential, not
accepted in v1; a node credential has no fallback.

`biscuit-python` is a dev dependency, imported only where a Biscuit is made
or read.

Run limits: the library's default limits stop a Datalog run after 1 ms of
wall-clock time. On a busy computer a check then fails by chance (a pack
got `expired`, or a query raised, so the request had no receipt). The
work of a credential check is bounded by the fact and iteration limits,
which do not depend on the computer, so the time limit here is only a
last stop (`RUN_TIME`). A run that breaks a limit is `bad_credential`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from anagram.core import signed
from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto import merkle
from anagram.core.crypto.hashing import tagged_hash
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.network.formats.strict import (
    HEX16,
    HEX32,
    HEX64,
    NODE_ID,
    PID,
    Refused,
    exact,
    fmt_time,
    hexval,
    intval,
    need,
    parse_time,
    sig_ok,
    sign,
)

if TYPE_CHECKING:
    import biscuit_auth as ba

FORMAT_BISCUIT = "biscuit-v3"
FORMAT_JSON = "anagram-json-v1"
FORMATS = (FORMAT_BISCUIT, FORMAT_JSON)
TAG_CREDENTIAL = "anagram/v1/net/member-credential"
TAG_SIGN_MEMBER_JSON = "anagram/v1/net/sign/member-credential"
MAX_LIFE = 86_400
CLOCK_SKEW = 300
MAX_PROOF_HASHES = 32
TAG_SIGN_LOG_ENTRY = "anagram/v1/enclave/sign/member-credential"
TAG_MEMBER_JOIN = "anagram/v1/net/member-join"
LOG_ENTRY_SCHEMA = "anagram.enclave.member_credential.v1"
MAX_EMAIL_TAGS = 3
RUN_FACTS = 1_000  # Datalog run limits of a credential check (see the module text)
RUN_ITERATIONS = 100
RUN_TIME = timedelta(seconds=60)


@dataclass(frozen=True)
class MemberFacts:
    network: str
    node: str
    subject: str  # hex of the person key (or group key)
    kind: str  # "person" or "group"
    issued: int
    expires: int
    control_head: int
    pid: str | None = None
    email_tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class NodeFacts:
    network: str
    node: str
    node_key: str
    node_kind: str
    domain: str
    ror: str | None
    issued: int
    expires: int


def _member_source(f: MemberFacts) -> str:
    lines = [
        'anagram("member_credential", 1);',
        f'network("{f.network}");',
        f'node("{f.node}");',
        f"subject(hex:{f.subject});",
        f'kind("{f.kind}");',
    ]
    if f.pid is not None:
        lines.append(f'pid("{f.pid}");')
    lines += [f"email_tag(hex:{t});" for t in sorted(f.email_tags)]
    lines += [
        f"control_head({f.control_head});",
        f"issued({fmt_time(f.issued)});",
        f"expires({fmt_time(f.expires)});",
        f"check if time($t), $t < {fmt_time(f.expires)};",
    ]
    return "\n".join(lines) + "\n"


def _node_source(f: NodeFacts) -> str:
    lines = [
        'anagram("node_credential", 1);',
        f'network("{f.network}");',
        f'node("{f.node}");',
        f"node_key(hex:{f.node_key});",
        f'node_kind("{f.node_kind}");',
        f'domain("{f.domain}");',
    ]
    if f.ror is not None:
        lines.append(f'ror("{f.ror}");')
    lines += [
        f"issued({fmt_time(f.issued)});",
        f"expires({fmt_time(f.expires)});",
        f"check if time($t), $t < {fmt_time(f.expires)};",
    ]
    return "\n".join(lines) + "\n"


def unb64url(text: str) -> bytes:
    try:
        return signed.unb64url(text)
    except FormatError as exc:
        raise Refused("bad_credential", "base64url") from exc


# biscuit-python 0.4.0 ships stubs that lag its runtime: `PrivateKey` and
# `PublicKey.from_bytes` take an `Algorithm`, `Algorithm.Ed25519` exists,
# `Biscuit.to_bytes` returns bytes, and `AuthorizerBuilder` has `limits` and
# `set_limits`. Each ignore below names one of these gaps; mypy reports an
# ignore that is no longer needed (`warn_unused_ignores`).


def _root_private(seed: bytes) -> ba.PrivateKey:
    import biscuit_auth as ba

    return ba.PrivateKey.from_bytes(seed, ba.Algorithm.Ed25519)  # type: ignore[call-arg, attr-defined]


def _root_public(public_hex: str) -> ba.PublicKey:
    import biscuit_auth as ba

    return ba.PublicKey.from_bytes(bytes.fromhex(public_hex), ba.Algorithm.Ed25519)  # type: ignore[call-arg, attr-defined]


def biscuit_source(facts: MemberFacts | NodeFacts) -> str:
    return _member_source(facts) if isinstance(facts, MemberFacts) else _node_source(facts)


def make_biscuit(facts: MemberFacts | NodeFacts, root: SigningKey) -> bytes:
    return make_biscuit_source(biscuit_source(facts), root)


def make_biscuit_source(source: str, root: SigningKey, extra_block: str | None = None) -> bytes:
    """A token from any Datalog source. The refusal vectors use it to make
    tokens that break the spec (an extra fact, rule, check or block)."""
    import biscuit_auth as ba

    token = ba.BiscuitBuilder(source).build(_root_private(root.seed()))
    if extra_block is not None:
        token = token.append(ba.BlockBuilder(extra_block))
    return token.to_bytes()  # type: ignore[return-value]  # bytes at run time


def token_blocks(raw: bytes, root_hex: str) -> list[str]:
    """The Datalog source of each block of a token whose signature verifies."""
    import biscuit_auth as ba

    token = ba.Biscuit.from_bytes(raw, _root_public(root_hex))
    return [token.block_source(i) for i in range(token.block_count())]


def _query(authorizer: Any, pred: str, arity: int) -> list[list[Any]]:
    import biscuit_auth as ba

    args = ", ".join(f"$v{i}" for i in range(arity))
    try:
        found = authorizer.query(ba.Rule(f"out({args}) <- {pred}({args})"))
    except Exception as exc:  # a run limit; the library raises its own class
        raise Refused("bad_credential", f"datalog run of {pred}") from exc
    return [f.terms for f in found]


def authorizer_builder(now: int) -> Any:
    """The authorizer of a credential check: the time fact and the run
    limits of this module, not the library's (see the module text)."""
    import biscuit_auth as ba

    builder = ba.AuthorizerBuilder(f"time({fmt_time(now)}); allow if true;")
    limits = builder.limits()  # type: ignore[attr-defined]  # stub gap, see above
    limits.max_facts, limits.max_iterations, limits.max_time = RUN_FACTS, RUN_ITERATIONS, RUN_TIME
    builder.set_limits(limits)  # type: ignore[attr-defined]  # stub gap, see above
    return builder


def _one(authorizer: Any, pred: str, kind: type) -> Any:
    rows = _query(authorizer, pred, 1)
    need(len(rows) == 1 and isinstance(rows[0][0], kind), "bad_credential", pred)
    return rows[0][0]


def _open_biscuit(raw: bytes, root_hex: str, now: int) -> tuple[Any, Any]:
    """Verify the signature and the block count. Return (token, authorizer).

    The authorizer is built but not run, so that the facts can be read and
    the block compared with the spec (bad_credential) before a failed check
    can give `expired`.
    """
    import biscuit_auth as ba

    try:
        token = ba.Biscuit.from_bytes(raw, _root_public(root_hex))
    except Exception as exc:  # the library raises several classes
        raise Refused("bad_credential", "biscuit signature") from exc
    need(token.block_count() == 1, "bad_credential", "attenuation blocks")
    return token, authorizer_builder(now).build(token)


def _exact_block(token: Any, facts: MemberFacts | NodeFacts) -> None:
    """The block holds the facts and the check of the spec, and nothing else.

    Both sides are printed by the library, so the comparison does not depend
    on our own formatting.
    """
    import biscuit_auth as ba

    try:
        want = str(ba.BlockBuilder(biscuit_source(facts)))
    except Exception as exc:  # a fact value that is not valid Datalog
        raise Refused("bad_credential", "facts") from exc
    need(token.block_source(0) == want, "bad_credential", "fact, rule or check outside the spec")


def _authorize(authorizer: Any, issued: int, expires: int, now: int) -> None:
    """Run the check of the token, then the time rules of the facts."""
    need(issued <= now + CLOCK_SKEW, "bad_credential", "issued in the future")
    try:
        authorizer.authorize()
    except Exception as exc:
        raise Refused("expired", "credential check failed") from exc
    need(now < expires, "expired", "credential")
    need(issued >= now - MAX_LIFE, "expired", "issued more than the longest life ago")


def _marker(authorizer: Any, marker: str) -> None:
    need(_query(authorizer, "anagram", 2) == [[marker, 1]], "bad_credential", "marker")


def read_member_biscuit(raw: bytes, node_key_hex: str, now: int) -> MemberFacts:
    token, a = _open_biscuit(raw, node_key_hex, now)
    _marker(a, "member_credential")
    kind = _one(a, "kind", str)
    need(kind in ("person", "group"), "bad_credential", "kind")
    pids = _query(a, "pid", 1)
    tags = sorted(t[0].hex() for t in _query(a, "email_tag", 1))
    need(len(pids) == (1 if kind == "person" else 0), "bad_credential", "pid")
    need(kind == "person" or not tags, "bad_credential", "email_tag")
    facts = MemberFacts(
        network=_one(a, "network", str),
        node=_one(a, "node", str),
        subject=_one(a, "subject", bytes).hex(),
        kind=kind,
        issued=int(_one(a, "issued", object).timestamp()),
        expires=int(_one(a, "expires", object).timestamp()),
        control_head=_one(a, "control_head", int),
        pid=pids[0][0] if pids else None,
        email_tags=tuple(tags),
    )
    check_member_facts(facts)
    _exact_block(token, facts)
    _authorize(a, facts.issued, facts.expires, now)
    return facts


def read_node_biscuit(raw: bytes, roster_key_hex: str, now: int) -> NodeFacts:
    token, a = _open_biscuit(raw, roster_key_hex, now)
    _marker(a, "node_credential")
    rors = _query(a, "ror", 1)
    need(len(rors) <= 1, "bad_credential", "ror")
    facts = NodeFacts(
        network=_one(a, "network", str),
        node=_one(a, "node", str),
        node_key=_one(a, "node_key", bytes).hex(),
        node_kind=_one(a, "node_kind", str),
        domain=_one(a, "domain", str),
        ror=rors[0][0] if rors else None,
        issued=int(_one(a, "issued", object).timestamp()),
        expires=int(_one(a, "expires", object).timestamp()),
    )
    need(0 < facts.expires - facts.issued <= MAX_LIFE, "bad_credential", "life")
    _exact_block(token, facts)
    _authorize(a, facts.issued, facts.expires, now)
    return facts


def check_member_facts(f: MemberFacts) -> None:
    need(bool(NODE_ID.match(f.node)) and bool(HEX32.match(f.subject)), "bad_credential", "ids")
    need(f.pid is None or bool(PID.match(f.pid)), "bad_credential", "pid")
    need(len(f.email_tags) <= MAX_EMAIL_TAGS, "bad_credential", "email_tag count")
    need(all(HEX32.match(t) for t in f.email_tags), "bad_credential", "email_tag")
    need(0 < f.expires - f.issued <= MAX_LIFE, "bad_credential", "life")


# The bespoke fallback (`anagram-json-v1`): the same facts as signed JSON.


def member_json(f: MemberFacts, node_key: SigningKey) -> JsonObject:
    doc = {
        "control_head": f.control_head,
        "email_tags": list(f.email_tags),
        "expires": fmt_time(f.expires),
        "issued": fmt_time(f.issued),
        "kind": f.kind,
        "network": f.network,
        "node": f.node,
        "pid": f.pid,
        "schema": "anagram.member_credential.v1",
        "subject": f.subject,
    }
    return sign(doc, TAG_SIGN_MEMBER_JSON, node_key)


def read_member_json(raw: bytes, node_key_hex: str, now: int) -> MemberFacts:
    from anagram.core.canonical import CanonicalError, loads_canonical

    try:
        doc = loads_canonical(raw)
    except (CanonicalError, ValueError) as exc:
        raise Refused("bad_credential", "json") from exc
    names = {"control_head", "email_tags", "expires", "issued", "kind", "network", "node"}
    names |= {"pid", "schema", "signature", "subject"}
    try:
        exact(doc, names, "member credential")
        need(doc["schema"] == "anagram.member_credential.v1", "bad_credential", "schema")
        need(sig_ok(doc, TAG_SIGN_MEMBER_JSON, node_key_hex), "bad_credential", "signature")
        tags = doc["email_tags"]
        need(isinstance(tags, list) and tags == sorted(set(tags)), "bad_credential", "tags")
        facts = MemberFacts(
            network=doc["network"],
            node=doc["node"],
            subject=hexval(doc["subject"], HEX32, "subject"),
            kind=doc["kind"],
            issued=parse_time(doc["issued"], "issued"),
            expires=parse_time(doc["expires"], "expires"),
            control_head=intval(doc["control_head"], 0, 2**53 - 1, "control_head"),
            pid=doc["pid"],
            email_tags=tuple(tags),
        )
    except Refused as exc:
        if exc.code == "bad_message":
            raise Refused("bad_credential", str(exc)) from exc
        raise
    need(facts.kind in ("person", "group"), "bad_credential", "kind")
    need((facts.pid is not None) == (facts.kind == "person"), "bad_credential", "pid")
    check_member_facts(facts)
    need(now < facts.expires, "expired", "credential")
    return facts


def credential_hash(raw: bytes) -> bytes:
    return tagged_hash(TAG_CREDENTIAL, raw)


def member_commit(subject_hex: str, salt_hex: str) -> str:
    """The join commitment of a new member (spec/network.md 6.5): it names
    the subject only for someone who knows the random salt (the app, the
    node and the enclave), so the public log shows a new member, not who."""
    data = bytes.fromhex(subject_hex) + bytes.fromhex(salt_hex)
    return tagged_hash(TAG_MEMBER_JOIN, data).hex()


def log_entry_body(f: MemberFacts, raw: bytes, signer_hex: str, member: str | None) -> JsonObject:
    """The `member_credential` entry of enclave-trust.md 2.3, without its
    signature. `member` is the join commitment on the first credential of a
    member at the node (a join entry), else null (a renewal)."""
    return {
        "credential_hash": credential_hash(raw).hex(),
        "expires": fmt_time(f.expires),
        "kind": "member_credential",
        "member": member,
        "node_id": f.node,
        "schema": LOG_ENTRY_SCHEMA,
        "signer": signer_hex,
    }


def log_entry(
    f: MemberFacts, raw: bytes, node_key: SigningKey, member: str | None = None
) -> JsonObject:
    """The signed log entry. Ed25519 is deterministic, so the entry is too."""
    body = log_entry_body(f, raw, node_key.public_bytes().hex(), member)
    return sign(body, TAG_SIGN_LOG_ENTRY, node_key)


def check_join(proof: JsonObject, index: int) -> tuple[int, str]:
    """The `join` of a log proof (network.md 6.5): the index of the
    member's join entry, at or before this entry, and its salt."""
    join = proof["join"]
    exact(join, {"index", "salt"}, "join")
    at = intval(join["index"], 0, index, "join index")
    return at, hexval(join["salt"], HEX16, "join salt")


def check_log_proof(
    proof: Any, f: MemberFacts, raw: bytes, node_key_hex: str, root_at: Mapping[int, bytes]
) -> None:
    """Rebuild the entry from the credential and prove it is in the log.

    `root_at` maps a tree size to a root that the verifier trusts
    (enclave-trust.md). The pack carries only the entry signature: every other
    field of the entry comes from the credential and the roster.
    """
    exact(proof, {"entry_signature", "hashes", "index", "join", "tree_size"}, "log proof")
    size = intval(proof["tree_size"], 1, 2**53 - 1, "tree_size")
    index = intval(proof["index"], 0, size - 1, "index")
    join_at, salt = check_join(proof, index)
    hashes = proof["hashes"]
    need(isinstance(hashes, list) and len(hashes) <= MAX_PROOF_HASHES, "bad_message", "hashes")
    path = [bytes.fromhex(hexval(h, HEX32, "hash")) for h in hashes]
    member = member_commit(f.subject, salt) if join_at == index else None
    entry = log_entry_body(f, raw, node_key_hex, member)
    entry["signature"] = hexval(proof["entry_signature"], HEX64, "entry_signature")
    need(sig_ok(entry, TAG_SIGN_LOG_ENTRY, node_key_hex), "bad_credential", "log entry signature")
    root = root_at.get(size)
    if root is None:
        raise Refused("bad_credential", "no trusted root for tree_size")
    leaf = merkle.leaf_hash(canonical_json(entry))
    need(merkle.verify_inclusion(leaf, index, size, path, root), "bad_credential", "inclusion")
