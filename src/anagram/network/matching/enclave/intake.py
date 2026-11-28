"""How the writer opens and checks one sealed request
(spec/enclave-messages.md section 3.3, in order; spec/pack.md 7.1).

1. length, magic and class (`bad_envelope`);
2. the intake key is this instance's (`unknown_instance_key`);
3. the attestation digest is the current document's (`stale_attestation`);
4. the signed time is safe (`clock_unsafe`);
5. HPKE opens and the padding is zero (`bad_envelope`);
6. the body checks of its type;
7. the subject is in this line's shard (`wrong_shard`);
8. the state checks of the ledger.

The first failure gives the receipt code. Every request gets one receipt,
also when it fails (the response key is in the header).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag

from anagram.core.canonical import JsonObject
from anagram.core.crypto import hpke
from anagram.network.formats import credential as cred
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import Network, subject_hash
from anagram.network.formats.strict import (
    MAX_SAFE,
    Refused,
    intval,
    need,
    parse_time,
    unpad,
)
from anagram.network.matching.enclave.funnel import line_digest
from anagram.network.matching.enclave.ledger import Ledger
from anagram.network.matching.trust.issuance import Issuance, check_join
from anagram.network.matching.trust.lines import shard

CLOCK_SKEW = packs.CLOCK_SKEW


@dataclass(frozen=True)
class Keys:
    """What steps 2, 3 and 5 need: this instance's intake key pair and the
    digest of its current attestation document."""

    intake_public: bytes
    intake_private: Any
    attestation: bytes


@dataclass
class Gate:
    """What the body and state checks need at one moment."""

    ledger: Ledger
    net: Network
    ctx: packs.Context
    node: str  # the node that relayed the request
    shard: tuple[int, int]  # (k, n) of this instance's line
    roster_fresh: bool  # a logged roster checkpoint at most 1 hour old
    issuance: Issuance  # join entries of each node and month, from the log
    issuance_limit: int  # `new_members_per_month` of the network policy

    @property
    def now(self) -> int:
        return self.ctx.now


def open_sealed(raw: bytes, keys: Keys, now: int | None) -> tuple[m.Request, bytes]:
    """Steps 1 to 5. `now` is None when the signed time is not safe."""
    req = m.parse_header(raw)
    need(req.intake == keys.intake_public, "unknown_instance_key")
    need(req.attestation == keys.attestation, "stale_attestation")
    need(now is not None, "clock_unsafe")
    head = raw[: m.HEADER]
    try:
        padded = hpke.open_sealed(keys.intake_private, raw[m.HEADER :], m.request_info(head))
    except (InvalidTag, ValueError) as exc:
        raise Refused("bad_envelope", "decrypt") from exc
    return req, unpad(padded)


def _in_shard(subject: str, gate: Gate) -> None:
    k, n = gate.shard
    need(shard(bytes.fromhex(subject), n) == k, "wrong_shard")


def _credential(doc: JsonObject, facts: cred.MemberFacts, gate: Gate) -> JsonObject:
    """Step 9 of pack.md 7.1 after the format checks: network state and the
    relaying node (spec/network.md 6.2 step 9; enclave-messages.md 9.2)."""
    need(gate.roster_fresh, "stale_roster", "no fresh roster checkpoint")
    raw = cred.unb64url(doc["credential"]["token"])
    gate.net.credential_usable(facts, raw)
    need(facts.node == gate.node, "bad_credential", "a pack comes through the node it names")
    _joined(doc["credential"]["log"], facts, gate)
    return {
        "expires": facts.expires,
        "hash": cred.credential_hash(raw).hex(),
        "issued": facts.issued,
        "node": facts.node,
        "pid": facts.pid,
        "email_tags": list(facts.email_tags),
        "control_head": facts.control_head,
        "token": doc["credential"]["token"],
    }


def _joined(proof: JsonObject, facts: cred.MemberFacts, gate: Gate) -> None:
    """Network.md 6.7: the member's join entry is a join entry of this node
    for this subject, made after the member's last removal at the node, and
    within the node's monthly limit of new members. A renewal points at the
    same join entry, so it never counts again."""
    at, salt = cred.check_join(proof, proof["index"])
    subj = subject_hash(bytes.fromhex(facts.subject))
    join = check_join(gate.issuance, at, facts.node, facts.subject, salt, gate.issuance_limit)
    key = (subj, facts.node)
    gone = None if key in gate.net.moved else gate.net.gone_by_node.get(key)
    after = gone is None or gate.issuance.appended_after(join) > gone
    need(after, "bad_credential", "the join entry is older than the member's removal")


def take_upload(body: bytes, gate: Gate) -> None:
    kind = m.upload_kind(body)
    if kind == "pack":
        _take_pack(body, gate)
    elif kind == "cover":
        _take_cover(body, gate)
    else:
        _take_withdrawal(body, gate)


def _take_pack(body: bytes, gate: Gate) -> None:
    doc, facts = packs.check_pack_bytes(body, gate.ctx)
    record = _credential(doc, facts, gate)
    subject = doc["subject"]
    _in_shard(subject, gate)
    created = parse_time(doc["created"], "created")
    approved = parse_time(doc["consent"]["approved_at"], "approved_at")
    gate.ledger.check_pack(subject, doc["version"], created, approved, gate.now)
    old = gate.ledger.subjects.get(subject)
    changed = old is None or old.pack is None or line_digest(old.pack) != line_digest(doc)
    gate.ledger.keep_pack(subject, doc, record, changed, facts.node, gate.now)


def _take_cover(body: bytes, gate: Gate) -> None:
    doc = m.read_json(body)
    facts = m.check_cover(doc, gate.ctx)
    _credential(doc, facts, gate)
    _in_shard(doc["subject"], gate)
    gate.ledger.check_cover(doc["subject"], gate.now)
    gate.ledger.keep_cover(doc["subject"], facts.node, doc["reply_key"], gate.now)


def _take_withdrawal(body: bytes, gate: Gate) -> None:
    """A withdrawal needs no credential: a person can always stop. Its
    slots go to the node of the subject's latest credential."""
    doc = m.check_withdrawal(m.read_json(body))
    need(parse_time(doc["created"], "created") <= gate.now + CLOCK_SKEW, "bad_message", "future")
    subject = doc["subject"]
    _in_shard(subject, gate)
    s = gate.ledger.subjects.get(subject)
    node = s.node if s is not None and s.node else gate.node
    gate.ledger.withdraw(subject, doc["version"], node, doc["reply_key"], gate.now)


def take_known(body: bytes, gate: Gate) -> None:
    known = packs.decode_known(body)
    intval(known.version, 1, MAX_SAFE, "known version")
    packs.check_age(known.created, gate.now)
    _in_shard(known.subject, gate)
    tags = [t for t, _ in known.entries]
    gate.ledger.keep_known(known.subject, known.version, known.created, tags, gate.now)


def take_answer(body: bytes, gate: Gate) -> str | None:
    """Keep one answer. Return the pair ID when it is a yes (the caller then
    tries the reveal). A filler (an answer checkpoint with nothing to send,
    section 5.3) is accepted and changes nothing."""
    kind, doc = m.answer_kind(body)
    if kind == "filler":
        gate.ledger.count("answer_fillers")
        return None
    subject = doc.get("subject")
    s = gate.ledger.subjects.get(subject) if isinstance(subject, str) else None
    tags = tuple(s.facts["email_tags"]) if s is not None and s.facts else ()
    m.check_answer(doc, tags)
    need(parse_time(doc["created"], "created") <= gate.now + CLOCK_SKEW, "bad_message", "future")
    _in_shard(doc["subject"], gate)
    need(subject_hash(bytes.fromhex(doc["subject"])) not in gate.net.bans, "revoked", "banned")
    gate.ledger.answer(doc["subject"], doc["proposal"], doc["choice"], doc["card"], gate.now)
    if doc["choice"] != "yes":
        return None
    return gate.ledger.proposals[doc["proposal"]].pair


class LogRoots(Mapping[int, bytes]):
    """Roots of the log at any size under a cosigned checkpoint (spec/pack.md
    5: "a root computed from the log tiles under a cosigned checkpoint")."""

    def __init__(self, root_at: Callable[[int], bytes], size: int) -> None:
        self._root_at = root_at
        self._size = size
        self._cache: dict[int, bytes] = {}

    def __getitem__(self, size: int) -> bytes:
        if not isinstance(size, int) or not 1 <= size <= self._size:
            raise KeyError(size)
        if size not in self._cache:
            self._cache[size] = self._root_at(size)
        return self._cache[size]

    def __iter__(self) -> Iterator[int]:
        return iter(range(1, self._size + 1))

    def __len__(self) -> int:
        return self._size
