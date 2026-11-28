"""The match protocol `anagram_pack_match.v1`.

The enclave decides pairs from packs only, in three steps:

1. **Filters** before any use of a pack: two different people;
   neither deny list names the peer's ROR ID, verified domain or node;
   neither block list names the peer; the charter rule of each match type
   (`any`, `inside`, `outside`); line scope (`inside` lines only for peers
   of the same node, `outside` only for other nodes); `hide` rules remove a
   line from the pair's input.
2. **Stage 1**: the enclave embeds each line text itself with
   the embedding model of the release, then for each want of a changed pack
   the nearest offers in scope by cosine, and the reverse, per match type;
   top `k`. No app supplies a vector.
3. **Joint judge**: one call reads both sides'
   visible lines and gives `{"fit_a", "fit_b", "type"}`; it is asked twice
   with the order swapped, and both orders must agree.

A pair may be proposed when both sides `fit` for one match type, the pair
may be proposed for that type (no open pair, no decline record of the
type, or a `not_now` that came back after 90 days), and each person's
eligible set for the type passes the anonymity rule of the release
(values from the `matching` descriptor). The sweep then **ranks**
these pairs by their best stage-1 score and takes them in that order while
both people stay under their weekly cap (the person's own value, at most
`weekly_cap_max`) and under the node rule: at most max(1, ceil(m /
50)) proposals to a person with a peer from any one other node in 28 days,
counting the proposals of the sweep itself. m is the number of
parties of that node in the sweep: each party is a live pack whose
member credential the enclave verified, so a pack that fails the check
adds nothing. So 50 fake members of one node give a target at most one
proposal in 4 weeks, and 500 real members of a large node at most 10.
Both people's delivery queues must also deliver the copy before the first
answer checkpoint: one slot item a day, behind the items already queued
and the copies of the same sweep. A
pair that only a cap, the node rule or a full delivery queue stopped
**waits** in the ledger and is ranked again at each later
sweep, best first, with no pack change; the other rules are checked again
each time, and a material change of either pack ends the wait (the pair is
judged again). The reasons of each copy are line
IDs of that person's own pack: the wants and offers of theirs that stage 1
matched (E1 option a).

The decision table (`decisions`, spec/matching.md 4) is one row for
each judged pair, with no pack text and no score; the audit counts its rows.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from anagram.core.canonical import JsonObject, canonical_json
from anagram.core.crypto.hashing import tagged_hash
from anagram.network.matching.enclave.decisions import Decisions, Row
from anagram.network.matching.enclave.ledger import Ledger, pair_key

PROTOCOL_ID = "anagram_pack_match.v1"
# The domain tag of the evidence hash of a decision row (spec/matching.md
# 4). The name is locked; the node-run matching room used it first.
TAG_EVIDENCE = "anagram/v1/room/evidence"
INPUT_KEY = "pack"
STAGE1_K = 50  # stage-1 default; the harness can override it
MAX_REASONS = 4  # spec/enclave-messages.md 6.4
# A waiting pair keeps its score in the sealed snapshot, and canonical JSON
# has no floats, so the ledger keeps it in millionths.
SCORE_SCALE = 1_000_000

# A stage-1 hit: (score, subject that owns the line, line ID).
type Hit = tuple[float, str, str]
# Stage-1 candidates: (a, b, type) with a < b -> its hits, best first.
type Candidates = dict[tuple[str, str, str], list[Hit]]


@dataclass(frozen=True)
class Party:
    """A live pack, with the roster record of its credential's node."""

    subject: str
    pid: str | None
    node: JsonObject  # roster node record: "id", "domain", "ror", ...
    pack: JsonObject

    @property
    def node_id(self) -> str:
        node_id: str = self.node["id"]  # a checked roster record
        return node_id

    def refs(self) -> set[str]:
        """The block references that name this person (spec/pack.md 3.8)."""
        out = {f"person:{self.subject}"}
        if self.pid:
            out.add(self.pid)
        return out


def _blocks(me: Party, peer: Party) -> bool:
    return bool(set(me.pack["block"]["people"]) & peer.refs())


def _denies(me: Party, peer: Party) -> bool:
    deny = me.pack["deny"]
    return (
        peer.node_id in deny["nodes"]
        or peer.node.get("domain") in deny["domains"]
        or (peer.node.get("ror") is not None and peer.node["ror"] in deny["rors"])
    )


def eligible(a: Party, b: Party) -> bool:
    """Filters that drop a pair before stage 1 (deny and block both ways)."""
    if a.subject == b.subject or (a.pid is not None and a.pid == b.pid):
        return False
    return not (_blocks(a, b) or _blocks(b, a) or _denies(a, b) or _denies(b, a))


def charter_allows(me: Party, peer: Party, kind: str) -> bool:
    charter = me.pack["charter"]
    if kind not in charter["protocols"]:
        return False
    rule = charter["rules"][kind]
    same = me.node_id == peer.node_id
    return bool(rule == "any" or (rule == "inside") == same)


def visible(me: Party, peer: Party, side: str, kind: str) -> list[JsonObject]:
    """My lines of one side that the pair may use for one match type."""
    same = me.node_id == peer.node_id
    hidden = {h["line"] for h in me.pack["block"]["hide"] if h["from"] in peer.refs()}
    return [
        line
        for line in me.pack["lines"][side]
        if kind in line["types"]
        and line["id"] not in hidden
        and (line["scope"] == "both" or (line["scope"] == "inside") == same)
    ]


def both_allow(a: Party, b: Party, kind: str) -> bool:
    return charter_allows(a, b, kind) and charter_allows(b, a, kind)


# ---- engines ----------------------------------------------------------------


class Embedder(ABC):
    """An embedding model of a release. It runs inside the enclave, so no
    line text leaves it."""

    @abstractmethod
    def embed(self, text: str) -> list[int]:
        """Return a vector of int8 values (-127 to 127)."""


def cosine(u: list[int], v: list[int]) -> float:
    if len(u) != len(v):
        return 0.0
    dot = sum(a * b for a, b in zip(u, v, strict=True))
    nu = sum(a * a for a in u) ** 0.5
    nv = sum(b * b for b in v) ** 0.5
    return dot / (nu * nv) if nu and nv else 0.0


class Vectors:
    """Line vectors made inside the enclave, cached by text. Not state: a
    restart makes them again from the packs."""

    def __init__(self, embedder: Embedder) -> None:
        self.embedder = embedder
        self._cache: dict[str, list[int]] = {}

    def of(self, text: str) -> list[int]:
        if text not in self._cache:
            self._cache[text] = self.embedder.embed(text)
        return self._cache[text]

    def score(self, a: JsonObject, b: JsonObject) -> float:
        return cosine(self.of(a["text"]), self.of(b["text"]))


@dataclass(frozen=True)
class Side:
    """One side of a judge call: the visible lines of one person."""

    wants: tuple[JsonObject, ...]
    offers: tuple[JsonObject, ...]


class JointJudge(ABC):
    """Option J: one decision from both sides' visible lines. Output enums
    only (no free text, A6)."""

    name: str = ""
    digest: str = ""

    @abstractmethod
    def decide(self, first: Side, second: Side, kinds: list[str]) -> JsonObject:
        """Return {"fit_a": "fit" | "pass", "fit_b": ..., "type": <kind>}."""


@dataclass
class Engines:
    """The models of a release: the embedder (as `Vectors`) and the joint
    judge. An `EngineFactory` builds them from the release's `model`
    descriptors and refuses a descriptor that names a model it does not
    run, or a digest that is not the model's. The host chooses the factory
    (the `simulated` build: `simulated_engines.simulated_engines`)."""

    vectors: Vectors
    judge: JointJudge


# The port: the `model` descriptors of a release -> its engines.
type EngineFactory = Callable[[Iterable[JsonObject]], Engines]


# ---- the sweep ----------------------------------------------------------------


@dataclass(frozen=True)
class Rules:
    """Values of the `matching` descriptor that the sweep applies."""

    anonymity_min_people: int
    anonymity_min_nodes: int
    weekly_cap_max: int
    answer_day: int

    @classmethod
    def of(cls, matching: JsonObject) -> Rules:
        body = matching["body"]
        return cls(
            body["anonymity_min_people"],
            body["anonymity_min_nodes"],
            body["weekly_cap_max"],
            body["answer_day"],
        )


@dataclass(frozen=True)
class Proposal:
    a: str
    b: str
    kind: str
    reasons: dict[str, list[str]]
    nodes: dict[str, str]  # subject -> node of its credential
    score: float = 0.0  # the best stage-1 score: the rank of the pair


@dataclass
class Taken:
    """What the sweep proposed so far, so the caps count it before the
    ledger does."""

    count: Counter[str] = field(default_factory=Counter)  # subject -> proposals
    nodes: Counter[tuple[str, str]] = field(default_factory=Counter)  # (subject, peer node)


@dataclass
class Sweep:
    """The result of one sweep: proposals to queue and the decision table."""

    proposals: list[Proposal] = field(default_factory=list)
    decisions: Decisions = field(default_factory=Decisions)
    disagreements: int = 0


def line_digest(pack: JsonObject) -> str:
    """Material change digest: the lines, the charter, scope
    and the lists that change the pair's input."""
    keys = ("block", "charter", "deny", "lines")
    return hashlib.sha256(canonical_json({k: pack[k] for k in keys})).hexdigest()


class PackMatch:
    id = PROTOCOL_ID
    input_key = INPUT_KEY

    def __init__(self, engines: Engines, rules: Rules, k: int = STAGE1_K) -> None:
        self.engines = engines
        self.rules = rules
        self.k = k

    # Stage 1.

    def stage1(self, parties: dict[str, Party], changed: set[str]) -> Candidates:
        """Candidate (a, b, type) with a < b, each with its hits
        (score, owner of the line, line ID), best first."""
        hits: Candidates = {}
        for x in sorted(changed & set(parties)):
            me = parties[x]
            for side, other in (("wants", "offers"), ("offers", "wants")):
                for kind in me.pack["charter"]["protocols"]:
                    self._nearest(me, parties, side, other, kind, hits)
        return {key: sorted(set(v), reverse=True) for key, v in hits.items()}

    def _nearest(
        self,
        me: Party,
        parties: dict[str, Party],
        side: str,
        other: str,
        kind: str,
        hits: Candidates,
    ) -> None:
        peers = [p for p in parties.values() if eligible(me, p) and both_allow(me, p, kind)]
        for line in me.pack["lines"][side]:
            found: list[Hit] = []
            for p in peers:
                if line not in visible(me, p, side, kind):
                    continue
                for o in visible(p, me, other, kind):
                    found.append((self.engines.vectors.score(line, o), p.subject, o["id"]))
            for score, peer, peer_line in sorted(found, reverse=True)[: self.k]:
                a, b = sorted((me.subject, peer))
                bucket = hits.setdefault((a, b, kind), [])
                bucket.append((score, me.subject, line["id"]))
                bucket.append((score, peer, peer_line))

    # Judge and rules.

    def judge(self, a: Party, b: Party, kinds: list[str]) -> JsonObject | None:
        """Ask twice with the order swapped; None if the orders disagree."""

        def side(me: Party, peer: Party) -> Side:
            wants = tuple(w for k in kinds for w in visible(me, peer, "wants", k))
            offers = tuple(o for k in kinds for o in visible(me, peer, "offers", k))
            return Side(_unique(wants), _unique(offers))

        sa, sb = side(a, b), side(b, a)
        first = self.engines.judge.decide(sa, sb, kinds)
        second = self.engines.judge.decide(sb, sa, kinds)
        swapped = {"fit_a": second["fit_b"], "fit_b": second["fit_a"], "type": second["type"]}
        return first if first == swapped else None

    def anonymous_enough(self, me: Party, parties: dict[str, Party], kind: str) -> bool:
        """Check that after my filters, the eligible set for the type holds
        at least `min_people` people in at least `min_nodes` nodes (for an
        `inside` rule: `min_people` members of my node)."""
        pool = [
            p
            for p in parties.values()
            if eligible(me, p)
            and both_allow(me, p, kind)
            and any(visible(p, me, s, kind) for s in ("wants", "offers"))
        ]
        if me.pack["charter"]["rules"][kind] == "inside":
            return len(pool) >= self.rules.anonymity_min_people
        nodes = {p.node_id for p in pool}
        return (
            len(pool) >= self.rules.anonymity_min_people
            and len(nodes) >= self.rules.anonymity_min_nodes
        )

    def under_cap(self, ledger: Ledger, me: Party, now: int, taken: Taken) -> bool:
        """The person's weekly cap: the value of the pack, at most the
        release's `weekly_cap_max`."""
        cap = min(me.pack["charter"]["weekly_cap"], self.rules.weekly_cap_max)
        made = ledger.recent_proposals(me.subject, now) + taken.count[me.subject]
        return bool(made < cap)

    @staticmethod
    def node_room(
        ledger: Ledger, me: Party, peer: Party, now: int, taken: Taken, members: Counter[str]
    ) -> bool:
        """C44, C47: proposals to me from one other node in 28 days, under
        the limit for the size of that node in this sweep."""
        return ledger.node_room(
            me.subject,
            me.node_id,
            peer.node_id,
            now,
            members=members[peer.node_id],
            taken=taken.nodes[(me.subject, peer.node_id)],
        )

    def stop(
        self,
        ledger: Ledger,
        pa: Party,
        pb: Party,
        now: int,
        taken: Taken,
        members: Counter[str],
    ) -> str | None:
        """Why the pair must wait for a later sweep (the audit count), or
        None. The pair waits when a person is at the weekly cap or the node
        rule, or when a person's queue cannot deliver the copy before the
        first checkpoint (spec/enclave-messages.md 6.5). So no copy waits
        too long in a queue and leaves the peer with a one-sided proposal."""
        if not (
            self.under_cap(ledger, pa, now, taken)
            and self.under_cap(ledger, pb, now, taken)
            and self.node_room(ledger, pa, pb, now, taken, members)
            and self.node_room(ledger, pb, pa, now, taken, members)
        ):
            return "cap_stops"
        day = self.rules.answer_day
        if not all(ledger.deliverable(x.subject, day, taken.count[x.subject]) for x in (pa, pb)):
            return "queue_stops"
        return None

    # The sweep.

    def sweep(self, ledger: Ledger, parties: dict[str, Party], now: int) -> Sweep:
        changed = {s for s in parties if ledger.subjects[s].changed}
        out = Sweep()
        rows = []
        ready: list[Proposal] = []
        candidates = self.stage1(parties, changed)
        for a, b in sorted({(a, b) for a, b, _ in candidates}):
            digests = [line_digest(parties[a].pack), line_digest(parties[b].pack)]
            if ledger.decided.get(pair_key(a, b)) == digests:
                continue  # one decision for each pair and material change
            ledger.decided[pair_key(a, b)] = digests
            kinds = sorted(k for x, y, k in candidates if (x, y) == (a, b))
            verdict = self.judge(parties[a], parties[b], kinds)
            if verdict is None:
                out.disagreements += 1
                continue
            kind = verdict["type"]
            mutual = verdict["fit_a"] == verdict["fit_b"] == "fit"
            rows.append(Row.make(a, b, mutual, kind, kind, _evidence(parties[a], parties[b])))
            if mutual and self._may(ledger, parties, a, b, kind, now):
                hits = candidates[(a, b, kind)]
                reasons = {s: _reasons(hits, s) for s in (a, b)}
                nodes = {s: parties[s].node_id for s in (a, b)}
                ready.append(Proposal(a, b, kind, reasons, nodes, hits[0][0]))
        for s in changed:
            ledger.subjects[s].changed = False
        ready += self.waiting(ledger, parties, now, {(p.a, p.b, p.kind) for p in ready})
        out.proposals = self.rank(ledger, parties, ready, now)
        out.decisions = Decisions.of(rows)
        return out

    def _may(
        self, ledger: Ledger, parties: dict[str, Party], a: str, b: str, kind: str, now: int
    ) -> bool:
        pa, pb = parties[a], parties[b]
        return (
            ledger.may_propose(a, b, kind, now)
            and self.anonymous_enough(pa, parties, kind)
            and self.anonymous_enough(pb, parties, kind)
        )

    def waiting(
        self, ledger: Ledger, parties: dict[str, Party], now: int, fresh: set[tuple[str, str, str]]
    ) -> list[Proposal]:
        """The pairs that `stop` held in an earlier sweep
        and that may still be proposed: both packs live and unchanged, and
        every other rule still holds. A material change ends the wait (the
        pair is judged again); a pair that another rule now stops ends."""
        out = []
        for key, w in sorted(ledger.waiting.items()):
            a, b, kind = w["a"], w["b"], w["kind"]
            if (a, b, kind) in fresh or a not in parties or b not in parties:
                continue  # judged again in this sweep, or a pack is dormant
            digests = [line_digest(parties[a].pack), line_digest(parties[b].pack)]
            if digests != w["digests"] or not self._may(ledger, parties, a, b, kind, now):
                del ledger.waiting[key]
                continue
            nodes = {s: parties[s].node_id for s in (a, b)}
            out.append(Proposal(a, b, kind, w["reasons"], nodes, w["score"] / SCORE_SCALE))
        return out

    def rank(
        self, ledger: Ledger, parties: dict[str, Party], ready: list[Proposal], now: int
    ) -> list[Proposal]:
        """Best first, then the caps and the queues (`stop`). A pair that
        `stop` holds waits for a later sweep (`waiting`)."""
        taken = Taken()
        members = node_members(parties)
        out = []
        for p in sorted(ready, key=lambda p: (-p.score, p.a, p.b, p.kind)):
            pa, pb = parties[p.a], parties[p.b]
            key = pair_key(p.a, p.b, p.kind)
            stop = self.stop(ledger, pa, pb, now, taken, members)
            if stop is not None:
                ledger.count(stop)
                ledger.waiting[key] = {
                    "a": p.a,
                    "b": p.b,
                    "digests": [line_digest(pa.pack), line_digest(pb.pack)],
                    "kind": p.kind,
                    "reasons": p.reasons,
                    "score": round(p.score * SCORE_SCALE),
                }
                continue
            ledger.waiting.pop(key, None)
            taken.count.update((p.a, p.b))
            taken.nodes.update([(p.a, pb.node_id), (p.b, pa.node_id)])
            out.append(p)
        return out


def node_members(parties: dict[str, Party]) -> Counter[str]:
    """C47a: m of each node, the parties of the sweep whose credential
    names it. A party is a live pack with a verified credential
    (`Matching.party`), so this counts members with matching on."""
    return Counter(p.node_id for p in parties.values())


def _unique(lines: tuple[JsonObject, ...]) -> tuple[JsonObject, ...]:
    seen: dict[str, JsonObject] = {}
    for line in lines:
        seen.setdefault(line["id"], line)
    return tuple(seen[k] for k in sorted(seen))


def _reasons(hits: list[Hit], subject: str) -> list[str]:
    """Up to 4 of my own line IDs that stage 1 matched for the pair and
    type, at half the pair's best score or more: best first, then sorted."""
    best = hits[0][0] if hits else 0.0
    mine: list[str] = []
    for score, owner, line_id in hits:
        if owner == subject and line_id not in mine and score >= best / 2:
            mine.append(line_id)
    return sorted(mine[:MAX_REASONS])


def _evidence(a: Party, b: Party) -> str:
    """What the decision used, by hash only (spec/matching.md 4)."""
    used = [[p.subject, p.pack["version"], line_digest(p.pack)] for p in (a, b)]
    return tagged_hash(TAG_EVIDENCE, canonical_json(used)).hex()
