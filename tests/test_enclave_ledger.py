"""Decline records, answer checkpoints and the node rule of the enclave
ledger (spec/enclave-trust.md 7.1; spec/enclave-messages.md 5.3, 6.4, 6.5;
W5).

A `no` keeps the pair apart for 365 days for the declined match type only.
The record belongs to the person who declined: it stays when the other
person withdraws and comes back, it goes when the decliner withdraws, and
the other person never sees it. The two copies of a proposal share three
answer checkpoints and one expiry.
"""

from __future__ import annotations

import json

import pytest

from anagram.network.formats.strict import DAY, Refused, fmt_time
from anagram.network.matching.enclave.ledger import (
    DECLINE_LIFE,
    NODE_GAP,
    Ledger,
    Subject,
    cut,
    decline_id,
    tombstone_id,
)

A, B, C = "a" * 64, "b" * 64, "c" * 64
NODE = "node-" + "0" * 32
OTHER = "node-" + "1" * 32
NODES = dict.fromkeys((A, B, C), NODE)
T = "research_fit"
T2 = "method_help"
DAY0 = 20_500
NOW = DAY0 * DAY + 8 * 3_600
EXPIRES = fmt_time(NOW + 30 * DAY)


def ledger() -> Ledger:
    led = Ledger()
    for s in (A, B, C):
        led.subjects[s] = Subject(
            version=1, pack={"expires": EXPIRES, "version": 1}, reply_key="00" * 32, node=NODE
        )
        led.subjects[s].uploaded = NOW
    return led


def b_says_no(led: Ledger) -> None:
    """A proposal for A and B, delivered at the next cut; B answers no."""
    pair = led.propose(A, B, T, {A: ["o01"], B: ["w01"]}, NOW, nodes=NODES)
    led.take_slots(DAY0 + 1)
    led.answer(B, led.pairs[pair].copies[B], "no", None, NOW + DAY)


def withdraw_and_return(led: Ledger, subject: str, at: int) -> None:
    led.withdraw(subject, 5, NODE, "00" * 32, at)
    led.keep_pack(
        subject,
        {"expires": EXPIRES, "reply_key": "00" * 32, "version": 6},
        {},
        True,
        NODE,
        at + DAY,
    )


def test_a_no_keeps_the_pair_apart_after_the_other_person_returns() -> None:
    led = ledger()
    b_says_no(led)
    withdraw_and_return(led, A, NOW + 2 * DAY)
    assert not any(A in k for k in led.history)  # A's withdrawal erased the history
    assert not led.may_propose(A, B, T, NOW + 3 * DAY)
    assert not led.may_propose(B, A, T, NOW + 3 * DAY)
    assert led.may_propose(A, C, T, NOW + 3 * DAY)


def test_a_no_blocks_only_the_declined_match_type() -> None:
    """C46: the same pair is proposed again for another match type."""
    led = ledger()
    b_says_no(led)
    later = NOW + 30 * DAY
    led.expire(later)
    assert not led.may_propose(A, B, T, later)
    assert led.may_propose(B, A, T2, later)
    pair = led.propose(A, B, T2, {A: ["o02"], B: ["w02"]}, later, nodes=NODES)
    slots = led.take_slots(DAY0 + 31) or []
    delivered = {s.subject: s.item for s in slots if s.item and s.item["kind"] == "proposal"}
    assert set(delivered) == {A, B}
    assert {item["type"] for item in delivered.values()} == {T2}
    assert led.pairs[pair].type == T2


def test_the_record_holds_only_a_hash_and_an_expiry() -> None:
    led = ledger()
    b_says_no(led)
    assert led.declines == {tombstone_id(B): {decline_id(B, A, T): NOW + DAY + DECLINE_LIFE}}
    assert decline_id(B, A, T) != decline_id(A, B, T)
    assert decline_id(B, A, T) != decline_id(B, A, T2)


def test_the_decliner_withdrawing_deletes_the_record() -> None:
    led = ledger()
    b_says_no(led)
    withdraw_and_return(led, B, NOW + 2 * DAY)
    assert led.declines == {}
    assert led.may_propose(A, B, T, NOW + 3 * DAY)


def test_the_record_ends_after_365_days() -> None:
    led = ledger()
    b_says_no(led)
    withdraw_and_return(led, A, NOW + 2 * DAY)
    later = NOW + DAY + DECLINE_LIFE + 1
    assert led.may_propose(A, B, T, later)
    led.expire(later)
    assert led.declines == {}


def test_the_other_person_gets_the_same_slots_as_with_no_record() -> None:
    """A returns after B's no. A's day slot is the same `empty` as when no
    one ever declined: nothing in A's slots shows the record."""

    def a_slots(declined: bool) -> list:
        led = ledger()
        if declined:
            b_says_no(led)
        withdraw_and_return(led, A, NOW + 2 * DAY)
        led.subjects[A].queue.clear()
        led.subjects[A].uploaded = cut(DAY0 + 5) - 1
        return [(s.subject, s.item) for s in led.take_slots(DAY0 + 5) or [] if s.subject == A]

    assert a_slots(declined=True) == a_slots(declined=False) == [(A, None)]


# ---- nothing names a withdrawn subject after its tombstone (7.1) ------------

REPLY_A = "1" * 64


def delivered_pair(led: Ledger) -> str:
    """A proposal for A and B, delivered to both at the next cut."""
    led.subjects[A].reply_key = REPLY_A
    pair = led.propose(A, B, T, {A: ["o01"], B: ["w01"]}, NOW, nodes=NODES)
    led.take_slots(DAY0 + 1)
    return pair


def days_pass(led: Ledger) -> None:
    """30 days of cuts: expiry and day batches. A proposal of day 0 expires
    at the end of its last checkpoint, day 22."""
    for day in range(DAY0 + 2, DAY0 + 32):
        led.expire(cut(day))
        led.take_slots(day)


def a_withdraws_and_time_passes(led: Ledger) -> None:
    """A withdraws on day 1; then the days pass, so B's copy expires and
    A's slot state ends after 48 hours."""
    led.withdraw(A, 5, NODE, REPLY_A, NOW + DAY)
    days_pass(led)


def traces_of_a(led: Ledger) -> list[str]:
    """Every value in the snapshot form that is A's key, A's reply key, or a
    hash made from A's key, other than A's tombstone and a decline record
    that B owns about A (the two exceptions of 7.1)."""
    state = led.to_json()
    state["tombstones"].pop(tombstone_id(A), None)
    state["declines"].get(tombstone_id(B), {}).pop(decline_id(B, A, T), None)
    text = json.dumps(state)
    derived = {A, REPLY_A, tombstone_id(A)}
    for kind in (T, T2):
        derived |= {decline_id(A, x, kind) for x in (B, C)}
        derived |= {decline_id(x, A, kind) for x in (B, C)}
    return sorted(v for v in derived if v in text)


def test_the_peer_copy_expiring_writes_no_history_about_a() -> None:
    led = ledger()
    delivered_pair(led)
    a_withdraws_and_time_passes(led)
    assert led.history == {}
    assert traces_of_a(led) == []


def test_the_peer_saying_not_now_writes_no_history_about_a() -> None:
    led = ledger()
    pair = delivered_pair(led)
    led.answer(B, led.pairs[pair].copies[B], "not_now", None, NOW + DAY // 2)
    a_withdraws_and_time_passes(led)
    assert traces_of_a(led) == []


def test_a_no_after_the_withdrawal_keeps_only_the_decliners_record() -> None:
    led = ledger()
    pair = delivered_pair(led)
    b_copy = led.pairs[pair].copies[B]
    led.withdraw(A, 5, NODE, REPLY_A, NOW + DAY)
    led.answer(B, b_copy, "no", None, NOW + 2 * DAY)  # accepted while B's copy lives
    assert led.declines == {tombstone_id(B): {decline_id(B, A, T): NOW + 2 * DAY + DECLINE_LIFE}}
    days_pass(led)
    assert traces_of_a(led) == []
    assert not led.may_propose(A, B, T, NOW + 30 * DAY)
    assert led.may_propose(A, B, T2, NOW + 30 * DAY)  # C46: only the declined type


def test_a_reveal_that_went_out_leaves_no_history_about_a() -> None:
    """Queued reveals survive the withdrawal (6.3); after both went out and
    the copies expired, nothing names A."""
    led = ledger()
    pair = delivered_pair(led)
    for s in (A, B):
        led.answer(s, led.pairs[pair].copies[s], "yes", {"name": s[:4]}, NOW + DAY // 2)
    led.reveal(pair, {A: {"kind": "reveal", "peer": B}, B: {"kind": "reveal", "peer": A}}, NOW)
    a_withdraws_and_time_passes(led)
    assert led.history == {}
    assert traces_of_a(led) == []


def test_a_known_upload_and_an_old_answer_after_the_withdrawal_write_nothing() -> None:
    led = ledger()
    pair = delivered_pair(led)
    a_copy = led.pairs[pair].copies[A]
    led.withdraw(A, 5, NODE, REPLY_A, NOW + DAY)
    assert led.keep_known(A, 2, NOW + DAY + 60, ["ab" * 32], NOW + DAY + 60) is False
    with pytest.raises(Refused, match="unknown_proposal"):
        led.answer(A, a_copy, "yes", {"name": "A"}, NOW + DAY + 60)
    days_pass(led)
    assert traces_of_a(led) == []


def test_a_withdrawal_after_a_cross_node_proposal_leaves_no_node_record() -> None:
    """The C44 record (peer nodes of each person) goes with the erasure."""
    led = ledger()
    led.subjects[A].reply_key = REPLY_A
    led.propose(A, B, T, {A: ["o01"], B: ["w01"]}, NOW, nodes={A: OTHER, B: NODE})
    assert led.peer_nodes == {A: {NODE: [NOW]}, B: {OTHER: [NOW]}}
    a_withdraws_and_time_passes(led)
    assert traces_of_a(led) == []
    assert A not in led.peer_nodes


# ---- answer checkpoints (enclave-messages.md 5.3) ----------------------


def test_both_copies_share_three_checkpoints_and_one_expiry() -> None:
    """A copy that waits in the queue still gets the pair's checkpoints, so
    the later copy never answers after the earlier copy expired."""
    led = ledger()
    sweep = cut(DAY0 + 1)
    first = led.propose(A, C, T, {A: ["o01"], C: ["w01"]}, sweep, nodes=NODES)
    pair = led.propose(A, B, T, {A: ["o02"], B: ["w02"]}, sweep, nodes=NODES)
    m = DAY0 + 1
    assert led.pairs[pair].checkpoints == [m + 7, m + 14, m + 21]
    assert led.pairs[pair].expires == (m + 22) * DAY
    items = {}
    for day in range(m, m + 3):  # A gets one proposal a day: the second waits
        for s in led.take_slots(day) or []:
            if s.item and s.item["kind"] == "proposal":
                items[(s.subject, s.item["id"])] = (day, s.item)
    copies = led.pairs[pair].copies
    day_a, item_a = items[(A, copies[A])]
    day_b, item_b = items[(B, copies[B])]
    assert (day_a, day_b) == (m + 1, m)
    assert item_a["checkpoints"] == item_b["checkpoints"]
    assert item_a["expires"] == item_b["expires"] == fmt_time((m + 22) * DAY)
    assert led.pairs[first].checkpoints == led.pairs[pair].checkpoints


def test_a_copy_not_delivered_before_the_first_checkpoint_is_dropped() -> None:
    """The queue wait ends at the first checkpoint: every delivered copy
    has all three checkpoints. The peer's copy ends at the expiry."""
    led = ledger()
    sweep = cut(DAY0 + 1)
    pairs = [
        led.propose(A, x, T, {A: ["o01"], x: ["w01"]}, sweep + i, nodes={A: NODE, x: f"n{i}"})
        for i, x in enumerate([B] + [f"{i:064x}" for i in range(1, 9)])
        if led.subjects.setdefault(x, Subject(version=1, reply_key="00" * 32)) is not None
    ]
    m = DAY0 + 1
    got = []
    for day in range(m, m + 23):
        led.expire(cut(day))
        for s in led.take_slots(day) or []:
            if s.subject == A and s.item and s.item["kind"] == "proposal":
                got.append(day)
    assert got == list(range(m, m + 7))  # 7 of 9 copies: days m to m + 6
    dropped = led.pairs.get(pairs[-1])
    assert dropped is None or dropped.state == "ended"


def test_a_mutual_yes_reveals_from_the_first_checkpoint() -> None:
    led = ledger()
    pair = led.propose(A, B, T, {A: ["o01"], B: ["w01"]}, cut(DAY0 + 1), nodes=NODES)
    led.take_slots(DAY0 + 1)
    for s in (A, B):  # early answers (an app sends only at checkpoints)
        led.answer(s, led.pairs[pair].copies[s], "yes", {"name": s[:4]}, NOW + DAY)
    first = led.pairs[pair].checkpoints[0]
    assert led.ready_pairs(first * DAY - 1) == []
    assert led.ready_pairs(first * DAY) == [pair]


def test_an_answer_at_the_last_checkpoint_is_before_the_expiry() -> None:
    led = ledger()
    pair = led.propose(A, B, T, {A: ["o01"], B: ["w01"]}, cut(DAY0 + 1), nodes=NODES)
    led.take_slots(DAY0 + 1)
    last = led.pairs[pair].checkpoints[-1]
    led.answer(A, led.pairs[pair].copies[A], "no", None, last * DAY + 23 * 3_600)
    with pytest.raises(Refused, match="unknown_proposal"):
        led.answer(B, led.pairs[pair].copies[B], "no", None, (last + 1) * DAY)


# ---- one proposal from one other node in 4 weeks ----------------------


def test_the_node_rule_counts_other_nodes_for_28_days() -> None:
    led = ledger()
    led.propose(A, B, T, {A: ["o01"], B: ["w01"]}, NOW, nodes={A: NODE, B: OTHER})
    assert not led.node_room(A, NODE, OTHER, NOW + NODE_GAP - 1, members=1)
    assert led.node_room(A, NODE, OTHER, NOW + NODE_GAP, members=1)
    assert led.node_room(A, NODE, NODE, NOW, members=0)  # the own node has no such limit
    led.expire(NOW + NODE_GAP)
    assert led.peer_nodes == {}
