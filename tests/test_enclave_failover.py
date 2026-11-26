"""Writer failover (spec/enclave-trust.md 5.7), end to end on the
in-process world of enclavekit.

Instance one writes the line; instance two holds the state key after a
standby handoff. Alice and Bob both say yes; the reveal is decided in a
cosigned epoch. Then one stops with no warning: one request is in its
memory only. After one's lease ends, the release key names two the writer
and both independent witnesses cosign it. Two loads the latest cosigned
epoch and goes on: every receipt is there, the lost request gets a receipt
when the app sends it again, both reveals go out, and the old writer, if it
comes back, writes nothing.
"""

from __future__ import annotations

import pytest
from enclavekit import HOUR, LINE, World, line

from anagram.network.formats.strict import DAY, Refused
from anagram.network.matching.trust.lines import line_forked, line_writer

TEXT = "Single-particle cryo-EM map refinement of membrane proteins"
OTHER = "Molecular dynamics simulations of membrane transporters"


def morning(w: World, people: tuple, day: int) -> None:
    """08:00: each app uploads a fresh pack (credentials last 24 hours) and
    reads its slot."""
    w.to_day(day)
    for p in people:
        w.upload(p)
        w.read_slots(p)


@pytest.fixture(scope="module")
def story() -> dict:
    w = World(answer_day=2)
    one = w.writer()
    two = w.instance("two", w.rel)
    two.register()
    w.publish()
    return _run(w, one, two)


def _run(w: World, one, two) -> dict:
    out: dict = {"world": w, "one": one, "two": two}
    two.accept_hand_off(one.hand_off(two.document, w.rel, standby=True))
    one.finish_hand_off()
    w.advance(HOUR)
    out["roles_after_standby"] = (one.role, two.role)

    alice = w.person(
        "Alice Okafor", "A", {"offers": [line("o01", TEXT)], "wants": [line("w01", OTHER)]}
    )
    bob = w.person(
        "Bob Lindqvist", "B", {"offers": [line("o01", OTHER)], "wants": [line("w01", TEXT)]}
    )
    carol = w.person(
        "Carol Nakamura",
        "A",
        {"offers": [line("o01", "Alpine pollinators")], "wants": [line("w01", "Beetles")]},
    )
    out.update(alice=alice, bob=bob)
    people = (alice, bob, carol)
    for p in people:
        w.upload(p)
    d0 = w.t // DAY
    morning(w, people, d0 + 1)
    for p in (alice, bob):
        item = p.items[-1][1]
        assert item["kind"] == "proposal"
        p.client.choose(item["id"], "yes", p.card)

    # The answer day: both yes, and a cosigned epoch decides the reveal.
    morning(w, people, d0 + 2)
    morning(w, people, d0 + 3)
    yes = {p.name: w.send_answers(p)[0] for p in (alice, bob)}
    w.advance(HOUR)
    out["reveals_decided"] = one.ledger.audit.get("reveals", 0)

    # A request that only one's memory holds, then one stops.
    lost = alice.client.upload_known(1, [])
    w.instances.remove(one)
    w.advance(25 * HOUR)  # every lease of one ends
    out["writer_before"] = line_writer(w.log.view(), LINE, w.trust.roots)
    w.trust.fail_over(LINE, two.instance_id)
    w.publish()
    w.advance(HOUR)
    out["roles_after_failover"] = two.role
    out["view"] = w.log.view()

    out["yes_receipts"] = [w.receipt(p, yes[p.name]) for p in (alice, bob)]
    alice.client.resend()  # the same bytes, sealed to one's key
    w.advance(HOUR)
    out["lost_receipt"] = w.receipt(alice, lost)
    alice.client.refresh()  # the code says: fetch the attestation bundle again
    again = alice.client.upload_known(1, [])  # sealed to two
    w.advance(HOUR)
    out["resealed_receipt"] = w.receipt(alice, again)

    w.to_day(w.t // DAY + 1)
    out["slots"] = {p.name: w.read_slots(p) for p in (alice, bob)}

    # One comes back: it sees the failover and writes nothing.
    size = len(w.log.entries)
    w.instances.append(one)
    w.tick()
    out["one_back"] = one.role, one.state_key
    out["epochs_by_one"] = [e for e in w.log.entries[size:] if e["signer"] == one.keys.output_hex]
    return out


def test_the_standby_holds_the_key_and_the_writer_stays(story: dict) -> None:
    assert story["roles_after_standby"] == ("writer", "holder")


def test_the_holder_takes_over_only_by_the_failover_entry(story: dict) -> None:
    assert story["writer_before"] == story["one"].instance_id
    assert story["roles_after_failover"] == "writer"
    assert not line_forked(story["view"], LINE, story["world"].trust.roots)


def test_no_receipt_is_lost(story: dict) -> None:
    assert [r["status"] for r in story["yes_receipts"]] == ["accepted", "accepted"]
    assert story["lost_receipt"]["reason"] == "unknown_instance_key"
    assert story["resealed_receipt"]["status"] == "accepted"


def test_both_reveals_go_out_after_the_failover(story: dict) -> None:
    assert story["reveals_decided"] == 1
    slots = story["slots"]
    assert slots["Alice Okafor"]["kind"] == slots["Bob Lindqvist"]["kind"] == "reveal"
    assert slots["Alice Okafor"]["peer"] == story["bob"].subject
    assert slots["Bob Lindqvist"]["peer"] == story["alice"].subject


def test_the_old_writer_comes_back_and_writes_nothing(story: dict) -> None:
    assert story["one_back"] == ("retired", None)
    assert story["epochs_by_one"] == []


def test_the_witnesses_refuse_a_failover_while_the_writer_lease_lives() -> None:
    w = World()
    two = w.instance("two", w.rel)
    two.register()
    w.publish()
    two.accept_hand_off(w.writer().hand_off(two.document, w.rel, standby=True))
    w.writer().finish_hand_off()
    w.advance(HOUR)
    with pytest.raises(Refused, match="lease"):
        w.trust.fail_over(LINE, two.instance_id)


def test_the_writer_adds_a_holder_only_on_the_successor_ready_note() -> None:
    """`/v1/handoff/finish` carries the successor's signed `ready` note: no
    other caller can make the writer write the epoch that adds a holder."""
    w = World()
    one = w.writer()
    two, three = w.instance("two", w.rel), w.instance("three", w.rel)
    two.register()
    three.register()
    w.publish()
    with pytest.raises(Refused, match="no handoff"):
        one.check_ready(two.ready({}))
    msg = one.hand_off(two.document, w.rel, standby=True)
    two.accept_hand_off(msg)
    note = two.ready(msg)
    for junk in (
        None,
        [],
        {},
        {**note, "signature": "00" * 64},
        {**note, "signature": "zz"},
        {**note, "handoff": "00" * 32},
        three.ready(msg),  # a note from another instance
        two.ready({**msg, "counter": 99}),  # a note for another message
    ):
        with pytest.raises(Refused):
            one.check_ready(junk)
    one.check_ready(note)
    one.finish_hand_off()
    assert two.instance_id in w.log.entries[-1]["holders"]
