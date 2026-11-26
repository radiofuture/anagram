"""The match protocol anagram_pack_match.v1 (enclave/funnel.py), with
the ranking under the weekly cap and the node rule."""

from __future__ import annotations

import copy
import json
import secrets
from typing import cast

import pytest

from anagram.core.canonical import canonical_json
from anagram.network.formats.roster import Network
from anagram.network.formats.strict import DAY, Refused
from anagram.network.matching.enclave.funnel import (
    Engines,
    PackMatch,
    Party,
    Proposal,
    Rules,
    Side,
    Vectors,
    charter_allows,
    eligible,
    line_digest,
    node_members,
    visible,
)
from anagram.network.matching.enclave.ledger import Ledger, Subject, node_limit
from anagram.network.matching.enclave.pairs import Matching
from anagram.network.matching.enclave.simulated_engines import (
    FAKE_EMBED_NAME,
    FakeEmbedder,
    FakeJointJudge,
    fake_embedder_digest,
    simulated_engines,
)

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
T = "research_fit"
NOW = 1_795_608_000


def node(label: str) -> dict:
    return {
        "affiliation": f"Lab {label}",
        "domain": f"lab-{label}.example.org",
        "id": "node-" + label * 32,
        "ror": f"0abcde{label}12",
    }


def ln(lid: str, text: str, scope: str = "both") -> dict:
    return {"id": lid, "scope": scope, "text": text, "types": [T]}


def pack(offer: str, want: str, rule: str = "any", version: int = 1, cap: int = 3) -> dict:
    return {
        "block": {"hide": [], "people": []},
        "charter": {"protocols": [T], "rules": {T: rule}, "weekly_cap": cap},
        "deny": {"domains": [], "nodes": [], "rors": []},
        "lines": {"offers": [ln("o01", offer)], "wants": [ln("w01", want)]},
        "version": version,
    }


def party(subject: str, label: str, p: dict) -> Party:
    return Party(subject, f"pid:{subject[:32]}", node(label), p)


@pytest.fixture
def pair() -> tuple[Party, Party]:
    return party("a" * 64, "a", pack(CRYO, MD)), party("b" * 64, "b", pack(MD, CRYO))


def engines() -> Engines:
    vectors = Vectors(FakeEmbedder())
    return Engines(vectors, FakeJointJudge(vectors))


def test_deny_by_node_domain_and_ror(pair: tuple[Party, Party]) -> None:
    a, b = pair
    assert eligible(a, b)
    for key, value in (
        ("nodes", b.node["id"]),
        ("domains", b.node["domain"]),
        ("rors", b.node["ror"]),
    ):
        denying = copy.deepcopy(a.pack)
        denying["deny"][key] = [value]
        assert not eligible(Party(a.subject, a.pid, a.node, denying), b)
        assert not eligible(b, Party(a.subject, a.pid, a.node, denying))  # both ways


def test_block_by_subject_or_pid(pair: tuple[Party, Party]) -> None:
    a, b = pair
    for ref in (f"person:{b.subject}", b.pid):
        blocking = copy.deepcopy(a.pack)
        blocking["block"]["people"] = [ref]
        assert not eligible(Party(a.subject, a.pid, a.node, blocking), b)


def test_two_keys_of_one_person_are_not_a_pair(pair: tuple[Party, Party]) -> None:
    """Two subject keys with one pid are one person: never a pair."""
    a, b = pair
    assert not eligible(a, Party(b.subject, a.pid, b.node, b.pack))


def test_charter_rules_and_line_scope(pair: tuple[Party, Party]) -> None:
    a, b = pair
    same = party("c" * 64, "a", pack(MD, CRYO))
    inside = Party(a.subject, a.pid, a.node, pack(CRYO, MD, rule="inside"))
    assert charter_allows(inside, same, T) and not charter_allows(inside, b, T)
    scoped = copy.deepcopy(a.pack)
    scoped["lines"]["offers"][0]["scope"] = "inside"
    me = Party(a.subject, a.pid, a.node, scoped)
    assert visible(me, same, "offers", T) and not visible(me, b, "offers", T)


def test_hide_removes_a_line_for_one_peer(pair: tuple[Party, Party]) -> None:
    a, b = pair
    hiding = copy.deepcopy(a.pack)
    hiding["block"]["hide"] = [{"from": b.pid, "line": "o01"}]
    me = Party(a.subject, a.pid, a.node, hiding)
    assert visible(me, b, "offers", T) == []
    assert visible(me, party("c" * 64, "c", pack(MD, CRYO)), "offers", T)


def test_joint_judge_is_the_same_in_both_orders(pair: tuple[Party, Party]) -> None:
    a, b = pair
    judge = engines().judge
    sa = Side(tuple(a.pack["lines"]["wants"]), tuple(a.pack["lines"]["offers"]))
    sb = Side(tuple(b.pack["lines"]["wants"]), tuple(b.pack["lines"]["offers"]))
    first, second = judge.decide(sa, sb, [T]), judge.decide(sb, sa, [T])
    assert first == {"fit_a": "fit", "fit_b": "fit", "type": T}
    assert (second["fit_a"], second["fit_b"]) == (first["fit_b"], first["fit_a"])


def test_engines_refuse_a_model_this_build_does_not_run() -> None:
    judge = FakeJointJudge(Vectors(FakeEmbedder()))
    good = [
        {"body": {"digest": fake_embedder_digest(), "name": FAKE_EMBED_NAME, "role": "embed"}},
        {"body": {"digest": judge.digest, "name": judge.name, "role": "judge"}},
    ]
    simulated_engines(good)
    bad = copy.deepcopy(good)
    bad[1]["body"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="judge digest"):
        simulated_engines(bad)
    with pytest.raises(ValueError, match="embedding"):
        simulated_engines(good[1:])


def ledger_with(*parties: Party) -> Ledger:
    led = Ledger()
    for p in parties:
        led.subjects[p.subject] = Subject(version=1, pack=p.pack, changed=True, reply_key="00" * 32)
    return led


def test_sweep_proposes_the_pair_with_own_reasons(pair: tuple[Party, Party]) -> None:
    a, b = pair
    c = party("c" * 64, "c", pack("Field surveys of alpine pollinators", "Beetle phylogenetics"))
    led = ledger_with(a, b, c)
    match = PackMatch(engines(), Rules(2, 1, 3, 7))
    out = match.sweep(led, {p.subject: p for p in (a, b, c)}, NOW)
    assert [(p.a, p.b, p.kind) for p in out.proposals] == [(a.subject, b.subject, T)]
    assert out.proposals[0].reasons == {a.subject: ["o01", "w01"], b.subject: ["o01", "w01"]}
    assert out.disagreements == 0 and len(out.decisions.rows) == 3
    again = match.sweep(led, {p.subject: p for p in (a, b, c)}, NOW)
    assert again.proposals == []  # one decision for each pair and material change


def test_sweep_respects_the_anonymity_rule(pair: tuple[Party, Party]) -> None:
    a, b = pair
    match = PackMatch(engines(), Rules(2, 1, 3, 7))  # only one peer: under 2 people
    out = match.sweep(ledger_with(a, b), {p.subject: p for p in pair}, NOW)
    assert out.proposals == []


def queue_and_deliver(match: PackMatch, led: Ledger, proposals: list, now: int) -> None:
    """Queue the proposals of a sweep, then take the slots of the next
    day, as the service does at the cut: one item for each person."""
    for p in proposals:
        led.propose(
            p.a, p.b, p.kind, p.reasons, now, nodes=p.nodes, answer_day=match.rules.answer_day
        )
    led.take_slots(now // DAY + 1)


def run_days(match: PackMatch, led: Ledger, parties: dict[str, Party], days: int, churn) -> list:
    """Sweep once a day, queue each proposal and take the day's slots, as
    the service does. Each day `churn` may change packs (a material
    change), so the changed pairs are judged again."""
    made = []
    for day in range(days):
        now = NOW + day * DAY
        churn(day, led, parties)
        proposals = match.sweep(led, parties, now).proposals
        queue_and_deliver(match, led, proposals, now)
        made += [(day, p) for p in proposals]
    return made


def test_fifty_fake_members_of_one_node_get_one_proposal_in_four_weeks() -> None:
    """C44 (W7: 50 fit-made Sybils took 8.5 of a target's 11.5 proposals).
    The Sybils change their packs every day, so each day they are judged
    again; the target still gets at most one proposal from their node in
    each 4 weeks, and honest peers of other nodes take the other places."""
    target = party("f" * 64, "f", pack(CRYO, MD))
    sybils = [party(f"{i:064x}", "e", pack(MD, CRYO)) for i in range(1, 51)]
    honest = [party(label * 64, label, pack(MD, CRYO)) for label in "abc"]
    parties = {p.subject: p for p in (target, *sybils, *honest)}
    led = ledger_with(*parties.values())

    def churn(day: int, led: Ledger, parties: dict[str, Party]) -> None:
        for s in sybils:
            p = copy.deepcopy(parties[s.subject].pack)
            p["deny"]["nodes"] = [f"node-{day:032x}"]
            parties[s.subject] = Party(s.subject, s.pid, s.node, p)
            led.subjects[s.subject].pack, led.subjects[s.subject].changed = p, True

    match = PackMatch(engines(), Rules(2, 1, 3, 7))
    made = run_days(match, led, parties, 56, churn)
    to_target = [(day, p) for day, p in made if target.subject in (p.a, p.b)]
    from_sybils = [
        day
        for day, p in to_target
        if p.nodes[p.a] == "node-" + "e" * 32 or p.nodes[p.b] == "node-" + "e" * 32
    ]
    assert len(from_sybils) == 2  # one in each 4 weeks
    assert from_sybils[1] - from_sybils[0] >= 28
    met = {x for _, p in to_target for x in (p.a, p.b)}
    assert len({h.subject for h in honest} & met) >= 2
    assert led.audit["cap_stops"] > 0


def test_the_weekly_cap_is_the_persons_own_value() -> None:
    """C43: a person who asks for 1 a week gets 1, under a network maximum
    of 3, also when four peers fit in one sweep."""
    me = party("f" * 64, "f", pack(CRYO, MD, cap=1))
    peers = [party(label * 64, label, pack(MD, CRYO)) for label in "abcd"]
    parties = {p.subject: p for p in (me, *peers)}
    led = ledger_with(*parties.values())
    match = PackMatch(engines(), Rules(2, 1, 3, 7))
    made = run_days(match, led, parties, 1, lambda *_: None)
    assert len([p for _, p in made if me.subject in (p.a, p.b)]) == 1


def test_a_pair_stopped_by_the_cap_comes_back_in_a_later_week() -> None:
    """Five good fits and a cap of 3: three this week, the other two in the
    next week, best first, with no pack change (the cap only delays)."""
    me = party("f" * 64, "f", pack(CRYO, MD, cap=3))
    peers = [party(label * 64, label, pack(MD, CRYO)) for label in "abcde"]
    parties = {p.subject: p for p in (me, *peers)}
    led = ledger_with(*parties.values())
    match = PackMatch(engines(), Rules(2, 1, 3, 7))
    made = run_days(match, led, parties, 21, lambda *_: None)
    mine = [(d, p.b if p.a == me.subject else p.a) for d, p in made if me.subject in (p.a, p.b)]
    assert [d for d, _ in mine] == [0, 0, 0, 7, 7]
    assert {peer for _, peer in mine} == {p.subject for p in peers}
    assert led.waiting == {}


def test_a_waiting_pair_ends_when_another_rule_stops_it() -> None:
    """A pair waits only for a cap: a block list ends the wait."""
    me = party("f" * 64, "f", pack(CRYO, MD, cap=1))
    peers = [party(label * 64, label, pack(MD, CRYO)) for label in "ab"]
    parties = {p.subject: p for p in (me, *peers)}
    led = ledger_with(*parties.values())
    match = PackMatch(engines(), Rules(2, 1, 3, 7))
    first = run_days(match, led, parties, 1, lambda *_: None)
    stopped = next(p for p in peers if p.subject not in (first[0][1].a, first[0][1].b))
    assert len(led.waiting) == 1

    def block(day: int, led: Ledger, parties: dict[str, Party]) -> None:
        if day == 3:
            p = copy.deepcopy(parties[stopped.subject].pack)
            p["block"]["people"] = [f"person:{me.subject}"]
            parties[stopped.subject] = Party(stopped.subject, stopped.pid, stopped.node, p)
            led.subjects[stopped.subject].pack = p

    assert run_days(match, led, parties, 14, block) == []
    assert led.waiting == {}


def test_line_digest_follows_material_fields(pair: tuple[Party, Party]) -> None:
    a, _ = pair
    later = copy.deepcopy(a.pack)
    later["version"] = 2
    assert line_digest(later) == line_digest(a.pack)
    later["deny"]["nodes"] = ["node-" + "f" * 32]
    assert line_digest(later) != line_digest(a.pack)


# ---- the node rule by node size ----------------------------------

BIG = "node-" + "e" * 32


def big_node_world(members: int, fits: int | None = None) -> tuple[Party, dict[str, Party], Ledger]:
    """A target of node f and `members` peers of node e. The first `fits`
    peers (default: all) fit the target; the others have unrelated packs
    but still count in m. The target's weekly cap is 10, so in 14 days the
    weekly cap allows 20 and only the node rule stops."""
    target = party("f" * 64, "f", pack(CRYO, MD, cap=10))
    fits = members if fits is None else fits
    other = pack("Field surveys of alpine pollinators", "Beetle phylogenetics")
    peers = [
        party(f"{i:032x}" * 2, "e", pack(MD, CRYO) if i <= fits else other)
        for i in range(1, members + 1)
    ]
    parties = {p.subject: p for p in (target, *peers)}
    return target, parties, ledger_with(*parties.values())


def days_from_big_node(made: list, target: Party) -> list[int]:
    return [d for d, p in made if target.subject in (p.a, p.b) and BIG in p.nodes.values()]


@pytest.mark.parametrize(
    ("members", "limit"),
    [(0, 1), (1, 1), (5, 1), (50, 1), (51, 2), (100, 2), (499, 10), (500, 10), (501, 11)],
)
def test_node_limit_is_one_for_each_50_members(members: int, limit: int) -> None:
    assert node_limit(members) == limit


def test_a_node_of_500_members_gives_10_in_4_weeks_and_the_11th_waits() -> None:
    """C47: ceil(500 / 50) = 10. The 11th waits and goes out on the day the
    first 10 leave the 28-day window. To keep the test fast it starts at
    the ranking: 12 mutual pairs with the target are ready on day 0 (stage
    1 and the judge over 500 packs take about 30 s); then each day the
    waiting pairs are ranked again, as `sweep` does."""
    target, parties, led = big_node_world(500, fits=12)
    assert node_members(parties)[BIG] == 500
    match = PackMatch(engines(), Rules(2, 1, 10, 7))
    peers = sorted(s for s in parties if s != target.subject)[:12]
    ready = [
        Proposal(
            target.subject,
            peer,
            T,
            {target.subject: ["o01"], peer: ["w01"]},
            {target.subject: target.node_id, peer: BIG},
            1.0 - i / 100,
        )
        for i, peer in enumerate(peers)
    ]
    made = []
    for day in range(29):
        now = NOW + day * DAY
        ready += match.waiting(led, parties, now, set())
        proposals = match.rank(led, parties, ready, now)
        queue_and_deliver(match, led, proposals, now)
        made += [(day, p) for p in proposals]
        ready = []
    days = days_from_big_node(made, target)
    # The target's queue delivers 7 copies before the first checkpoint, so
    # the 8th to 10th go out one a day after it; the 11th and 12th wait for
    # the node rule until the first 7 leave the 28-day window.
    assert days == [0] * 7 + [1, 2, 3] + [28, 28]
    assert led.waiting == {}
    assert led.audit["cap_stops"] > 0


def test_a_node_of_5_members_gives_1_in_4_weeks() -> None:
    target, parties, led = big_node_world(5)
    match = PackMatch(engines(), Rules(2, 1, 10, 7))
    made = run_days(match, led, parties, 28, lambda *_: None)
    assert days_from_big_node(made, target) == [0]
    assert len(led.waiting) == 4  # the other 4 wait for a later sweep


@pytest.mark.parametrize("members", [0, 1])
def test_a_node_with_0_or_1_verified_packs_gives_1(members: int) -> None:
    """m = 0 (the peer's pack is no longer live in this sweep) or m = 1:
    the limit is 1."""
    target, peer = party("f" * 64, "f", pack(CRYO, MD)), party("1" * 64, "e", pack(MD, CRYO))
    led = ledger_with(target, peer)
    nodes = {target.subject: target.node_id, peer.subject: BIG}
    assert led.node_room(target.subject, target.node_id, BIG, NOW, members=members)
    reasons: dict[str, list[str]] = {target.subject: [], peer.subject: []}
    led.propose(target.subject, peer.subject, T, reasons, NOW, nodes=nodes)
    assert not led.node_room(target.subject, target.node_id, BIG, NOW + DAY, members=members)
    assert led.node_room(target.subject, target.node_id, BIG, NOW + 28 * DAY, members=members)


class StubNet:
    """The two parts of a network that `Matching.party` reads: the roster
    nodes and the credential check. Credentials of `bad` subjects fail."""

    network = "net-" + "0" * 32

    def __init__(self, nodes: list[dict], bad: set[str]) -> None:
        self.nodes = {n["id"]: n for n in nodes}
        self.bad = bad

    def credential_usable(self, facts: object, raw: bytes) -> None:
        if getattr(facts, "subject", None) in self.bad:
            raise Refused("bad_signature")


def facts(p: Party) -> dict:
    return {
        "control_head": 0,
        "expires": NOW + 7 * DAY,
        "issued": NOW - DAY,
        "node": p.node_id,
        "pid": p.pid,
        "token": "AA",
    }


@pytest.mark.parametrize(("bad", "from_big"), [(0, 2), (1, 1)])
def test_m_counts_only_packs_with_a_verified_credential(bad: int, from_big: int) -> None:
    """C47a: 51 packs of node e give a limit of 2. When the credential of
    one pack fails the check, that pack is not live, m is 50 and the limit
    is 1."""
    target, parties, led = big_node_world(51)
    for p in parties.values():
        led.subjects[p.subject].facts = facts(p)
    peers = sorted(s for s, p in parties.items() if p.node_id == BIG)
    net = StubNet([node("e"), node("f")], set(peers[:bad]))
    matching = Matching(
        cast(Network, net),
        PackMatch(engines(), Rules(2, 1, 10, 7)),
        lambda: secrets.token_hex(16),
        lambda _: None,
    )
    matching.sweep(led, NOW)
    assert len([p for p in led.pairs.values() if target.subject in (p.a, p.b)]) == from_big
    assert len(led.peer_nodes[target.subject][BIG]) == from_big


# ---- delivery before the first checkpoint ---------------------------------


def test_a_copy_is_proposed_only_if_its_queue_delivers_it_in_time() -> None:
    led = ledger_with(party("f" * 64, "f", pack(CRYO, MD)))
    s = led.subjects["f" * 64]
    s.queue = [{"item": {"kind": "ended", "proposal": "x"}, "queued": NOW}] * 5
    assert led.deliverable("f" * 64, 7, taken=1)  # position 6: day D + 6
    assert not led.deliverable("f" * 64, 7, taken=2)  # day D + 7 is the checkpoint
    assert not led.deliverable("f" * 64, 5)


def test_cap_10_with_answer_day_7_never_gives_a_one_sided_proposal() -> None:
    """Ten good fits in one sweep, a weekly cap of 10 and answer_day 7: the
    person's queue can deliver 7 copies before the first checkpoint, so 7
    pairs go out on day 0 and 3 wait. Each held pair goes out on a later
    day, when the queue has room. Every copy of every pair is delivered
    before its first checkpoint, and the safety net drops nothing."""
    me = party("f" * 64, "f", pack(CRYO, MD, cap=10))
    peers = [party(label * 64, label, pack(MD, CRYO)) for label in "0123456789"]
    parties = {p.subject: p for p in (me, *peers)}
    led = ledger_with(*parties.values())
    match = PackMatch(engines(), Rules(2, 1, 10, 7))
    made = run_days(match, led, parties, 21, lambda *_: None)
    mine = [d for d, p in made if me.subject in (p.a, p.b)]
    assert mine == [0] * 7 + [1, 2, 3]
    assert led.audit["queue_stops"] > 0
    assert "late_copies" not in led.audit
    assert led.waiting == {}
    for pair in led.pairs.values():
        copies = [led.proposals[pid] for pid in pair.copies.values()]
        assert len(copies) == 2
        assert all(c.day is not None and c.day < pair.checkpoints[0] for c in copies)


def test_the_safety_net_still_drops_a_copy_that_is_late() -> None:
    """A copy that a later item pushes past the first checkpoint is not
    delivered, and the audit counts it."""
    a, b = party("a" * 64, "a", pack(CRYO, MD)), party("b" * 64, "b", pack(MD, CRYO))
    led = ledger_with(a, b)
    nodes = {a.subject: a.node_id, b.subject: b.node_id}
    reasons: dict[str, list[str]] = {a.subject: ["o01"], b.subject: ["o01"]}
    pair_id = led.propose(a.subject, b.subject, T, reasons, NOW, nodes=nodes, answer_day=1)
    first = led.pairs[pair_id].checkpoints[0]
    led.subjects[a.subject].queue.insert(
        0, {"item": {"kind": "ended", "proposal": "x"}, "queued": NOW}
    )
    led.take_slots(first - 1)  # b gets its copy; a gets the `ended` item
    led.take_slots(first)  # a's copy is late
    assert led.audit["late_copies"] == 1
    assert led.pairs[pair_id].state == "ended"


def test_a_waiting_pair_fits_in_the_sealed_snapshot() -> None:
    """The snapshot is canonical JSON, which has no floats: the ledger keeps
    the score of a waiting pair as an integer, and the rank comes back."""
    me = party("f" * 64, "f", pack(CRYO, MD, cap=1))
    peers = [party(label * 64, label, pack(MD, CRYO)) for label in "ab"]
    parties = {p.subject: p for p in (me, *peers)}
    led = ledger_with(*parties.values())
    match = PackMatch(engines(), Rules(2, 1, 3, 7))
    run_days(match, led, parties, 1, lambda *_: None)
    (held,) = led.waiting.values()
    assert isinstance(held["score"], int)
    assert Ledger.from_json(json.loads(canonical_json(led.to_json()))).waiting == led.waiting
    (back,) = match.waiting(led, parties, NOW + DAY, set())
    assert 0 < back.score <= 1
