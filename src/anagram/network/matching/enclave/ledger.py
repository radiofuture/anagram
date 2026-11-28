"""The working state of the matching enclave and its state rules.

Everything that a sealed snapshot holds is here (spec/enclave-trust.md
section 6.1), and nothing else: the ledger has no keys, no cryptography and
no clock. The callers give it times and opaque values (packs, credential
facts, sealed receipts, sealed slots), so the same rules run in the enclave
service and in the reference scripts of the vectors (`intake_script`,
`slot_script` of spec/vectors/enclave-messages.json).

Rules, by section:

- packs, covers, withdrawals and known objects: version, daily rate and
  tombstone (spec/enclave-messages.md section 8; spec/pack.md sections 8
  and 9.3; spec/enclave-trust.md section 6.3);
- answers: one for each delivered, unexpired proposal (section 5.3);
- proposals in pairs with one set of answer checkpoints and one expiry for
  both copies; both or neither reveal, not before the first checkpoint;
  "ended" at the expiry whatever the cause (sections 5.3, 6.4 to 6.6; W4
  ruling 1);
- at most `node_limit(m)` proposals to a person from any one other node
  in 28 days, where m is the number of live packs of that node with a
  verified credential in the sweep (the sweep
  ranks with `node_room`);
- one slot a day by the one 48 hour rule, and a queue that survives a
  withdrawal (section 6.5; W4 findings H-b, H-d, re-check R1);
- deletion on withdrawal, removal and expiry (spec/enclave-trust.md 7.1);
- decline records: a `no` keeps the pair apart for 365 days for the declined
  match type, also after the other person withdraws and comes back; the
  decliner's own withdrawal deletes them (spec/enclave-trust.md 7.1).

A rule that refuses raises `Refused` with the receipt code of section 10.
"""

from __future__ import annotations

import math
import secrets
from collections.abc import Callable, Container
from dataclasses import asdict, dataclass, field

from anagram.core.canonical import JsonObject
from anagram.core.crypto.hashing import tagged_hash
from anagram.network.formats.strict import DAY, Refused, day_of, fmt_time, need, parse_time

HOUR = 3_600
SLOT_WINDOW = 48 * HOUR  # section 6.5: an upload in the 48 hours before the cut
CHECKPOINTS = 3  # section 5.3: answers leave on days m + a, m + 2a and m + 3a
ANSWER_DAY = 7  # the `answer_day` a of a production release
NODE_GAP = 28 * DAY  # C44: the window of the node rule, 4 weeks
MEMBERS_PER_PROPOSAL = 50  # C47: one more proposal in the window for each 50 members
NOT_NOW_GAP = 90 * DAY  # section 5.3: "not now" may come back after 90 days
WEEK = 7 * DAY
KNOWN_GAP = 6 * DAY  # section 8.2
RECEIPT_LIFE = 48 * HOUR  # section 8.5
TOMBSTONE_LIFE = (30 + 7 + 1) * DAY  # enclave-trust.md 6.3: pack + key overlap + margin
BATCH_DAYS = 2  # the node fetches the batch of day D before 00:00 UTC of day D
DECLINE_LIFE = 365 * DAY  # enclave-trust.md 7.1: a decline record lives 365 days
TAG_TOMBSTONE = "anagram/v1/enclave/tombstone"
TAG_DECLINE = "anagram/v1/enclave/decline"
ITEM_ORDER = {"reveal": 0, "ended": 1, "proposal": 2}
# The slot batch of one day: node -> [[address hex, sealed slot base64], ...].
type SlotBatch = dict[str, list[list[str]]]
ERASED = ""  # stands for an erased subject in a pair that the peer still holds  # section 6.5: queue order


def cut(day: int) -> int:
    """The cut of day D: 23:00:00 UTC of day D - 1 (section 2)."""
    return day * DAY - HOUR


def tombstone_id(subject: str) -> str:
    """Tombstones name a subject by a hash of its key (enclave-trust.md 6.3)."""
    return tagged_hash(TAG_TOMBSTONE, bytes.fromhex(subject)).hex()


def decline_id(decliner: str, other: str, kind: str) -> str:
    """A decline record names the pair and the declined match type by a
    hash of both keys, decliner first, and the type, so it is one-way: it
    says who said no only to whom, and for which type (7.1)."""
    data = bytes.fromhex(decliner) + bytes.fromhex(other) + kind.encode("ascii")
    return tagged_hash(TAG_DECLINE, data).hex()


def answer_plan(made: int, answer_day: int) -> tuple[list[int], int]:
    """The checkpoints (UTC days) and the expiry (Unix time) of a proposal
    made at `made` (section 5.3). Both copies of a pair share them, so
    the copies end at the same time and a later copy never answers after
    the earlier one expired. `m` is the day after the day of the sweep: the
    sweep runs at the cut (23:00 UTC), so `m` is the first slot day."""
    m = day_of(made) + 1
    checkpoints = [m + k * answer_day for k in range(1, CHECKPOINTS + 1)]
    return checkpoints, (checkpoints[-1] + 1) * DAY


def tombstone_refusal(tomb: JsonObject | None, version: int, created: int, now: int) -> str | None:
    """`tombstoned` while the tombstone lives and the message is not newer
    than it, in version and in time (spec/pack.md section 8)."""
    if tomb is None or now > tomb["time"] + TOMBSTONE_LIFE:
        return None
    if version <= tomb["version"] or created <= tomb["time"]:
        return "tombstoned"
    return None


def pair_key(a: str, b: str, kind: str = "") -> str:
    lo, hi = sorted((a, b))
    return f"{lo}|{hi}|{kind}" if kind else f"{lo}|{hi}"


@dataclass
class Subject:
    """What the enclave keeps for one subject key."""

    version: int = 0  # last accepted pack or withdrawal version (one counter)
    pack: JsonObject | None = None  # the newest accepted pack
    facts: JsonObject | None = None  # the credential facts of that pack, and its hash
    known: JsonObject | None = None  # {"version", "time", "tags"} while a pack is live
    node: str | None = None  # slot record: node of the latest credential
    reply_key: str | None = None  # slot record: current reply key (hex)
    uploaded: int | None = None  # slot record: time of the latest pack, cover or withdrawal
    rate_day: int | None = None  # the UTC day of the latest pack or cover
    queue: list[JsonObject] = field(default_factory=list)  # {"item", "queued"}
    changed: bool = False  # a material change since the last sweep


@dataclass
class Copy:
    """One person's copy of a proposal. `day` is the slot day that carried
    it and `expires` the pair's expiry; both are None until delivery."""

    subject: str
    pair: str
    type: str
    reasons: list[str]
    pack_version: int
    queued: int
    day: int | None = None
    expires: int | None = None
    answer: str | None = None
    card: JsonObject | None = None
    decline: str = ""  # decline_id(subject, peer, type): what a `no` of this copy records


@dataclass
class Pair:
    a: str
    b: str
    type: str
    copies: dict[str, str]  # subject -> proposal ID
    made: int
    state: str = "open"  # "open", "revealed" or "ended"
    checkpoints: list[int] = field(default_factory=list)  # answer days, shared (5.3)
    expires: int = 0  # 00:00 UTC of the day after the last checkpoint


@dataclass(frozen=True)
class Slot:
    """One entry of the day batch before sealing: `item` is None for empty."""

    node: str
    subject: str
    reply_key: str
    item: JsonObject | None


def _new_id() -> str:
    return secrets.token_hex(16)


def _prune(table: dict[str, dict[str, int]], keep: Callable[[int], bool]) -> None:
    """Drop the times that `keep` refuses from a table of owner -> {key:
    time}, and owners with nothing left."""
    for owner, records in list(table.items()):
        kept = {k: t for k, t in records.items() if keep(t)}
        if kept:
            table[owner] = kept
        else:
            del table[owner]


def node_limit(members: int) -> int:
    """C47: the proposals that one other node with `members` live, verified
    members may give one person in 28 days: max(1, ceil(m / 50))."""
    return max(1, math.ceil(members / MEMBERS_PER_PROPOSAL))


@dataclass
class Ledger:
    subjects: dict[str, Subject] = field(default_factory=dict)
    tombstones: dict[str, JsonObject] = field(default_factory=dict)  # tombstone ID -> record
    proposals: dict[str, Copy] = field(default_factory=dict)  # proposal ID -> copy
    pairs: dict[str, Pair] = field(default_factory=dict)
    history: dict[str, JsonObject] = field(default_factory=dict)  # pair_key(a, b, type) -> outcome
    # tombstone_id(decliner) -> {decline_id(decliner, other): expiry}
    declines: dict[str, dict[str, int]] = field(default_factory=dict)
    decided: dict[str, list[str]] = field(default_factory=dict)  # pair_key -> line digests
    made: dict[str, list[int]] = field(default_factory=dict)  # subject -> proposal times
    # subject -> {node of a peer of another node: proposal times in 28 days}
    peer_nodes: dict[str, dict[str, list[int]]] = field(default_factory=dict)
    # pair_key(a, b, type) -> a mutual pair that a cap or the node rule stopped
    waiting: dict[str, JsonObject] = field(default_factory=dict)
    batches: dict[str, JsonObject] = field(default_factory=dict)  # day -> {"made", "nodes"}
    receipts: dict[str, JsonObject] = field(default_factory=dict)  # request digest -> record
    audit: dict[str, int] = field(default_factory=dict)  # counts only (matching.md 7)
    max_seen: int = 0  # the largest signed time seen (enclave-trust.md 6.4)

    # ---- snapshot form ---------------------------------------------------

    def to_json(self) -> JsonObject:
        return asdict(self)

    @classmethod
    def from_json(cls, obj: JsonObject) -> Ledger:
        return cls(
            subjects={k: Subject(**v) for k, v in obj["subjects"].items()},
            tombstones=obj["tombstones"],
            proposals={k: Copy(**v) for k, v in obj["proposals"].items()},
            pairs={k: Pair(**v) for k, v in obj["pairs"].items()},
            history=obj["history"],
            declines=obj["declines"],
            decided=obj["decided"],
            made=obj["made"],
            peer_nodes=obj["peer_nodes"],
            waiting=obj["waiting"],
            batches=obj["batches"],
            receipts=obj["receipts"],
            audit=obj["audit"],
            max_seen=obj["max_seen"],
        )

    def count(self, name: str, n: int = 1) -> None:
        self.audit[name] = self.audit.get(name, 0) + n

    def _subject(self, subject: str) -> Subject:
        return self.subjects.setdefault(subject, Subject())

    def _upload(self, subject: str, node: str, reply_key: str, now: int) -> Subject:
        """A pack, a cover and a withdrawal count the same for slots."""
        s = self._subject(subject)
        s.node, s.reply_key, s.uploaded = node, reply_key, now
        return s

    # ---- packs, covers, withdrawals (section 8.1) -----------------------

    def check_pack(
        self, subject: str, version: int, created: int, approved_at: int, now: int
    ) -> None:
        tomb = self.tombstones.get(tombstone_id(subject))
        code = tombstone_refusal(tomb, version, created, now)
        need(code is None, "tombstoned", "older than the tombstone")
        if tomb is not None and tomb["reason"] == "withdrawn":
            need(approved_at > tomb["time"], "tombstoned", "no new consent after a withdrawal")
        s = self.subjects.get(subject)
        need(s is None or version > s.version, "old_version")
        need(s is None or s.rate_day != day_of(now), "rate_limited")

    def keep_pack(
        self, subject: str, pack: JsonObject, facts: JsonObject, changed: bool, node: str, now: int
    ) -> None:
        """The newest pack replaces the older one at once (pack.md 8)."""
        s = self._upload(subject, node, pack["reply_key"], now)
        s.version, s.rate_day = pack["version"], day_of(now)
        s.pack, s.facts = pack, facts
        s.changed = s.changed or changed

    def check_cover(self, subject: str, now: int) -> None:
        s = self.subjects.get(subject)
        need(s is None or s.rate_day != day_of(now), "rate_limited")

    def keep_cover(self, subject: str, node: str, reply_key: str, now: int) -> None:
        """A cover changes no matching state; it keeps only the slot record."""
        self._upload(subject, node, reply_key, now).rate_day = day_of(now)

    def withdraw(self, subject: str, version: int, node: str, reply_key: str, now: int) -> None:
        tomb = self.tombstones.get(tombstone_id(subject))
        s = self.subjects.get(subject)
        floor = max(s.version if s else 0, tomb["version"] if tomb else 0)
        need(version > floor, "old_version")
        self.erase(subject, version, now, "withdrawn")
        self._upload(subject, node, reply_key, now)

    def erase(self, subject: str, version: int, now: int, reason: str) -> None:
        """Delete what the enclave holds about the subject; keep queued
        reveals and the slot record; add a tombstone (enclave-trust.md 7.1)."""
        s = self.subjects.get(subject)
        if s is not None:
            s.pack = s.facts = s.known = None
            s.changed = False
            s.version = max(s.version, version)
            s.queue = [e for e in s.queue if e["item"]["kind"] == "reveal"]
        for pid in [p for p, c in self.proposals.items() if c.subject == subject]:
            self._drop_copy(pid)
        for p in self.pairs.values():  # pairs that live on only for the peer's copy
            p.a, p.b = (ERASED if x == subject else x for x in (p.a, p.b))
        for table in (self.decided, self.history, self.waiting):
            for key in [k for k in table if subject in k.split("|")[:2]]:
                del table[key]
        self.made.pop(subject, None)
        self.peer_nodes.pop(subject, None)
        if reason == "withdrawn":
            self.declines.pop(tombstone_id(subject), None)
        self.tombstones[tombstone_id(subject)] = {"reason": reason, "time": now, "version": version}
        self.count(f"erase_{reason}")

    # ---- known objects (section 8.2) -----------------------------------

    def keep_known(
        self, subject: str, version: int, created: int, tags: list[str], now: int
    ) -> bool:
        """Keep a known object only for a subject with a live pack (W4 M-i).
        Return False when the enclave keeps nothing."""
        s = self.subjects.get(subject)
        if s is None or s.pack is None:
            return False
        tomb = self.tombstones.get(tombstone_id(subject))
        need(tomb is None or created > tomb["time"], "tombstoned")
        if s.known is not None:
            need(version > s.known["version"], "old_version")
            need(now - s.known["time"] >= KNOWN_GAP, "rate_limited")
        s.known = {"tags": tags, "time": now, "version": version}
        return True

    # ---- proposals and answers (sections 5 and 6.4 to 6.6) --------------

    def propose(
        self,
        a: str,
        b: str,
        kind: str,
        reasons: dict[str, list[str]],
        now: int,
        new_id: Callable[[], str] = _new_id,
        *,
        nodes: dict[str, str],
        answer_day: int = ANSWER_DAY,
    ) -> str:
        """Queue one copy of a proposal for each person of the pair. The two
        copies have unrelated random IDs (section 6.4) and share the answer
        checkpoints and the expiry (5.3). `nodes` names the node of each
        person's credential, for the node rule."""
        pair_id = self._fresh(new_id)
        copies: dict[str, str] = {}
        for subject in (a, b):
            pid = self._fresh(new_id, copies.values())
            s = self.subjects[subject]
            peer = b if subject == a else a
            self.proposals[pid] = Copy(
                subject,
                pair_id,
                kind,
                sorted(reasons[subject]),
                s.version,
                now,
                decline=decline_id(subject, peer, kind),
            )
            copies[subject] = pid
            self._enqueue(s, {"id": pid, "kind": "proposal"}, now)
            self.made.setdefault(subject, []).append(now)
            if nodes[peer] != nodes[subject]:
                self.peer_nodes.setdefault(subject, {}).setdefault(nodes[peer], []).append(now)
        checkpoints, expires = answer_plan(now, answer_day)
        self.pairs[pair_id] = Pair(a, b, kind, copies, now, "open", checkpoints, expires)
        self.count("proposals")
        return pair_id

    def _fresh(self, new_id: Callable[[], str], also: Container[str] = ()) -> str:
        """A random ID not in use (section 6.4: a new one if it was used)."""
        while True:
            value = new_id()
            if value not in self.proposals and value not in self.pairs and value not in also:
                return value

    def recent_proposals(self, subject: str, now: int) -> int:
        """Proposals made for the subject in the last 7 days (weekly cap)."""
        times = [t for t in self.made.get(subject, []) if t > now - WEEK]
        if times:
            self.made[subject] = times
        else:
            self.made.pop(subject, None)
        return len(times)

    def deliverable(self, subject: str, answer_day: int, taken: int = 0) -> bool:
        """A new copy for `subject` goes out before the first checkpoint
        (section 6.5). The sweep runs at the cut of day D, so the copy can
        use the slots of days D to D + `answer_day` - 1, one item a day.
        It goes behind every item in the queue now and the `taken` copies
        of the running sweep."""
        s = self.subjects.get(subject)
        queued = len(s.queue) if s is not None else 0
        return queued + taken < answer_day

    def node_room(
        self, subject: str, own: str, peer: str, now: int, *, members: int, taken: int = 0
    ) -> bool:
        """C44, C47: fewer than `node_limit(members)` proposals to `subject`
        with a peer of the other node `peer` in the last 28 days, with the
        `taken` proposals of the running sweep. The person's own node is the
        trust boundary of its members (spec/network.md 8.6), so it has no
        such limit."""
        if own == peer:
            return True
        times = self.peer_nodes.get(subject, {}).get(peer, [])
        recent = sum(1 for t in times if now - t < NODE_GAP)
        return recent + taken < node_limit(members)

    def open_pair(self, a: str, b: str, kind: str) -> bool:
        return any(
            p.type == kind and {p.a, p.b} == {a, b} and p.state == "open"
            for p in self.pairs.values()
        )

    def answer(
        self, subject: str, proposal: str, choice: str, card: JsonObject | None, now: int
    ) -> None:
        c = self.proposals.get(proposal)
        if c is None or c.subject != subject or c.expires is None or now >= c.expires:
            raise Refused("unknown_proposal")
        need(c.answer is None, "already_answered")
        c.answer, c.card = choice, card if choice == "yes" else None
        if choice == "no":  # the copy holds the ID: the peer may be erased by now
            self.declines.setdefault(tombstone_id(subject), {})[c.decline] = now + DECLINE_LIFE

    def ready_pairs(self, now: int) -> list[str]:
        """Open pairs where both copies say yes, neither expired, and the
        first checkpoint has come: a mutual yes reveals at the first
        checkpoint where both have answered (5.3). An app sends answers
        only on checkpoint days, so this only holds back an early answer."""
        out = []
        for pair_id, p in sorted(self.pairs.items()):
            copies = [self.proposals.get(pid) for pid in p.copies.values()]
            if (
                p.state == "open"
                and (not p.checkpoints or now >= p.checkpoints[0] * DAY)
                and len(copies) == 2
                and all(
                    c is not None and c.answer == "yes" and c.expires and now < c.expires
                    for c in copies
                )
            ):
                out.append(pair_id)
        return out

    def copy_of(self, pair_id: str, subject: str) -> Copy:
        return self.proposals[self.pairs[pair_id].copies[subject]]

    def reveal(self, pair_id: str, items: dict[str, JsonObject], now: int) -> None:
        """Both reveal items in one state change (section 6.6). The cards
        leave the copies: they live on only inside the reveal items."""
        p = self.pairs[pair_id]
        p.state = "revealed"
        for pid in p.copies.values():
            self.proposals[pid].card = None
        self.queue_together(items, now)
        self.count("reveals")

    def queue_together(self, items: dict[str, JsonObject], now: int) -> None:
        for subject, item in items.items():
            self._enqueue(self.subjects[subject], item, now)

    def end_pair(self, pair_id: str) -> None:
        """No reveal for this pair. A delivered copy ends at its expiry; a
        copy that was not delivered is never delivered."""
        p = self.pairs[pair_id]
        if p.state != "open":
            return
        p.state = "ended"
        for pid in list(p.copies.values()):
            if self.proposals[pid].day is None:
                self._drop_copy(pid)

    def _drop_copy(self, pid: str) -> None:
        c = self.proposals.pop(pid)
        s = self.subjects.get(c.subject)
        if s is not None:
            s.queue = [e for e in s.queue if e["item"].get("id") != pid]
        p = self.pairs[c.pair]
        p.copies.pop(c.subject, None)
        self.end_pair(c.pair)  # may drop the peer's undelivered copy and close the pair
        if not p.copies and c.pair in self.pairs:
            self._close(c.pair)

    def _close(self, pair_id: str) -> None:
        p = self.pairs.pop(pair_id)
        if p.state == "revealed" and ERASED not in (p.a, p.b):
            self.history[pair_key(p.a, p.b, p.type)] = {"outcome": "met", "time": p.made}

    @staticmethod
    def _enqueue(s: Subject, item: JsonObject, now: int) -> None:
        """Reveals first, then ended, then proposals; first in, first out
        inside each kind (section 6.5)."""
        rank = ITEM_ORDER[item["kind"]]
        at = len(s.queue)
        for i, e in enumerate(s.queue):
            if ITEM_ORDER[e["item"]["kind"]] > rank:
                at = i
                break
        s.queue.insert(at, {"item": item, "queued": now})

    # ---- the day batch (sections 6.5 and 6.7) ---------------------------

    def take_slots(self, day: int) -> list[Slot] | None:
        """The slots of day D, made at its cut, in subject order. Pops one
        item for each subject. A batch that exists is never made again
        (None)."""
        if str(day) in self.batches:
            return None
        c = cut(day)
        out = []
        for subject in sorted(self.subjects):
            s = self.subjects[subject]
            if s.reply_key is None:
                continue
            item = self._next_item(s, day)
            if item is None and not (s.uploaded is not None and c - SLOT_WINDOW < s.uploaded <= c):
                continue
            out.append(Slot(s.node or "", subject, s.reply_key, item))
        for subject in list(self.subjects):
            self._forget_slot(subject, c)
        return out

    def _next_item(self, s: Subject, day: int) -> JsonObject | None:
        while s.queue:
            entry = s.queue.pop(0)
            item: JsonObject = entry["item"]
            if item["kind"] != "proposal":
                return item
            pid = item["id"]
            pair_id = self.proposals[pid].pair
            if day >= self.pairs[pair_id].checkpoints[0]:
                # A safety net only: the sweep proposes a pair only when both
                # queues can deliver the copy in time (`deliverable`), so a
                # later reveal or `ended` item that goes before it, or a
                # missed batch, is the only way here.
                self.count("late_copies")
                self.end_pair(pair_id)  # drops this undelivered copy
                continue
            return self._deliver(pid, day)
        return None

    def _deliver(self, pid: str, day: int) -> JsonObject:
        c = self.proposals[pid]
        pair = self.pairs[c.pair]
        c.day, c.expires = day, pair.expires
        return {
            "checkpoints": [fmt_time(d * DAY) for d in pair.checkpoints],
            "expires": fmt_time(c.expires),
            "id": pid,
            "kind": "proposal",
            "pack_version": c.pack_version,
            "protocol": f"anagram.fit.{c.type}.v1",
            "reasons": list(c.reasons),
            "type": c.type,
        }

    def _forget_slot(self, subject: str, c: int) -> None:
        """After 48 hours with no upload and an empty queue, delete the slot
        state. The reply key stays while a pack or a delivered copy is open,
        so a reveal that comes later still has a key to seal to; it gives a
        slot only by the rule of `take_slots`."""
        s = self.subjects[subject]
        if s.queue or s.uploaded is None or s.uploaded > c - SLOT_WINDOW:
            return
        if s.pack is not None or any(p.subject == subject for p in self.proposals.values()):
            return
        del self.subjects[subject]

    def store_batch(self, day: int, counter: int, nodes: SlotBatch) -> None:
        """`counter` is the next state epoch: the batch is in its snapshot."""
        self.batches[str(day)] = {"made": counter, "nodes": nodes}
        for old in [d for d in self.batches if int(d) <= day - BATCH_DAYS]:
            del self.batches[old]

    def batch(self, day: int, cosigned: int) -> SlotBatch | None:
        """The batch of day D once a cosigned epoch holds it, else None."""
        b = self.batches.get(str(day))
        if b is None or b["made"] > cosigned:
            return None
        nodes: SlotBatch = b["nodes"]
        return nodes

    # ---- receipts (sections 4.4 and 8.5) -------------------------------

    def add_receipt(self, digest: str, node: str, counter: int, sealed: str, now: int) -> None:
        self.receipts[digest] = {"arrived": counter, "node": node, "sealed": sealed, "time": now}

    def receipt(self, digest: str, node: str, cosigned: int) -> str | None:
        """Released after a cosigned epoch written after the request arrived;
        only to the node that relayed it."""
        r = self.receipts.get(digest)
        if r is None or r["node"] != node or r["arrived"] > cosigned:
            return None
        sealed: str = r["sealed"]
        return sealed

    # ---- time (sections 5.3, 6.4; pack.md 8; enclave-trust.md 6.3) ------

    def expire(self, now: int) -> None:
        for pid in sorted(self.proposals):
            if pid in self.proposals:
                self._expire_copy(pid, now)
        for subject, s in sorted(self.subjects.items()):
            if s.pack is not None and parse_time(s.pack["expires"], "expires") <= now:
                self.erase(subject, s.version, now, "expired")
        for table, life in ((self.tombstones, TOMBSTONE_LIFE), (self.receipts, RECEIPT_LIFE)):
            for key in [k for k, v in table.items() if v["time"] + life < now]:
                del table[key]
        self._prune_peer_nodes(now)
        _prune(self.declines, lambda t: t > now)

    def _prune_peer_nodes(self, now: int) -> None:
        """Keep only the proposal times that the node rule still counts."""
        for subject, by_node in list(self.peer_nodes.items()):
            kept = {
                n: recent
                for n, times in by_node.items()
                if (recent := [t for t in times if now - t < NODE_GAP])
            }
            if kept:
                self.peer_nodes[subject] = kept
            else:
                del self.peer_nodes[subject]

    def _expire_copy(self, pid: str, now: int) -> None:
        """At the pair's expiry: `ended` for a delivered copy of a pair with
        no reveal; a copy that was never delivered ends with no item."""
        c = self.proposals[pid]
        p = self.pairs[c.pair]
        if c.expires is None:
            if p.expires and p.expires <= now:
                self.end_pair(c.pair)
            return
        if c.expires > now:
            return
        if p.state != "revealed":
            self._enqueue(self.subjects[c.subject], {"kind": "ended", "proposal": pid}, now)
            self._remember(p, c, now)
        self._drop_copy(pid)

    def _remember(self, p: Pair, c: Copy, now: int) -> None:
        """The outcome of the pair for this type: `no` (its decline record
        keeps the pair apart for 365 days), or `not_now` (also no answer),
        which lets it come back after 90 days and a material change
        (section 5.3). Nothing
        is kept for a pair whose other person was erased (enclave-trust.md
        7.1): no row may name a subject after its tombstone."""
        if ERASED in (p.a, p.b):
            return
        key = pair_key(p.a, p.b, p.type)
        if c.answer == "no" or self.history.get(key, {}).get("outcome") == "no":
            self.history[key] = {"outcome": "no", "time": now}
        else:
            self.history[key] = {"outcome": "not_now", "time": now}

    def declined(self, decliner: str, other: str, kind: str, now: int) -> bool:
        records = self.declines.get(tombstone_id(decliner), {})
        expiry = records.get(decline_id(decliner, other, kind))
        return expiry is not None and expiry > now

    def may_propose(self, a: str, b: str, kind: str, now: int) -> bool:
        """A `no` blocks only its match type, for 365 days, through its
        decline record; a pair that met is not proposed again for
        the type; `not_now` comes back after 90 days."""
        if self.open_pair(a, b, kind):
            return False
        if self.declined(a, b, kind, now) or self.declined(b, a, kind, now):
            return False
        h = self.history.get(pair_key(a, b, kind))
        if h is None or h["outcome"] == "no":
            return True
        return bool(h["outcome"] == "not_now" and now - h["time"] >= NOT_NOW_GAP)
