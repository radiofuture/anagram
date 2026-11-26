"""The first end-to-end slice of the matching enclave (plan net 14b step 11).

Two nodes, four people, the `simulated` profile, real HTTP routes in one
process. One run of the story below; each test checks one part of it:

- Alice (node A) and Bob (node B) are a planted complementary pair. Both
  say yes on the fixed answer day. The enclave crashes after the second yes
  and before the next epoch; no receipt of the lost work was released, the
  apps send the same bytes again, and both reveals go out together.
- Carol (node A) and Dan (node B) are complementary too, but Dan's pack
  denies node A: no proposal. Dan lifts the deny; they get a proposal.
  Carol says yes, then withdraws before Dan's yes: no reveal, Dan's copy
  ends at its expiry, and Carol's old consent is refused by the tombstone.
- The other pairs do not fit: no proposal.
- After the reveals the line moves to a new release by the signed
  enclave-to-enclave handoff; the batch of the day is the same bytes before
  and after, and the new writer serves the later days.

The promise: before mutual yes, no byte of a person's pack text or identity
reaches a node or a peer; and a change to a peer that a person cannot see
does not change a byte of what that person gets (non-interference).
"""

from __future__ import annotations

import pytest
from enclavekit import HOUR, World, line

from anagram.network.formats import enclave as m
from anagram.network.formats.strict import DAY

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
FIELD = "Field surveys of alpine plant pollinators"
PHYLO = "Bayesian phylogenetics of beetle radiations"


def lines(offer: str, want: str) -> dict:
    return {"offers": [line("o01", offer)], "wants": [line("w01", want)]}


def cast(w: World, dan_offer: str = PHYLO) -> dict:
    return {
        "alice": w.person("Alice Okafor", "A", lines(CRYO, MD)),
        "bob": w.person("Bob Lindqvist", "B", lines(MD, CRYO)),
        "carol": w.person("Carol Nakamura", "A", lines(FIELD, PHYLO)),
        "dan": w.person("Dan Petrov", "B", lines(dan_offer, FIELD), deny_nodes=("A",)),
    }


def morning(w: World, people: list, day: int) -> None:
    """08:00 of `day`: each app uploads its pack again (a fresh credential
    keeps the pack live and gives the next slot) and reads today's slot."""
    w.to_day(day)
    for p in people:
        w.upload(p)
        w.read_slots(p)


@pytest.fixture(scope="module")
def story() -> dict:
    w = World(answer_day=2)
    c = cast(w)
    alice, bob, carol, dan = c["alice"], c["bob"], c["carol"], c["dan"]
    d0 = w.t // DAY
    out: dict = {"world": w, "d0": d0, **c}
    for p in c.values():
        w.upload(p)

    # D1: Alice and Bob get the proposal; Carol and Dan get empty slots.
    # Dan lifts the deny in the pack that his app uploads on D1.
    dan.deny["nodes"] = []
    morning(w, [alice, bob, carol, dan], d0 + 1)
    out["d1"] = {p.name: p.items[-1][1] for p in c.values()}
    alice.client.choose(alice.items[-1][1]["id"], "yes", alice.card)
    bob.client.choose(bob.items[-1][1]["id"], "yes", bob.card)

    # D2: Carol and Dan get their proposal (a material change of Dan's pack).
    morning(w, [alice, bob, carol, dan], d0 + 2)
    out["d2"] = {p.name: p.items[-1][1] for p in c.values()}
    carol.client.choose(carol.items[-1][1]["id"], "yes", carol.card)
    dan.client.choose(dan.items[-1][1]["id"], "yes", dan.card)
    out["early"] = alice.client.send_due() + bob.client.send_due()  # not yet due

    # D3: the answer day of Alice and Bob. Crash after both yes, before the epoch.
    morning(w, [alice, bob, carol, dan], d0 + 3)
    yes = [(alice, d) for d in w.send_answers(alice)] + [(bob, d) for d in w.send_answers(bob)]
    out["reveals_before_crash"] = w.writer().ledger.audit.get("reveals", 0)
    w.writer().restart()
    out["reveals_after_crash"] = w.writer().ledger.audit.get("reveals", 0)
    w.advance(HOUR)
    out["receipts_lost"] = [w.receipt(p, d) for p, d in yes]
    alice.client.resend()
    bob.client.resend()
    w.advance(HOUR)
    out["receipts_resent"] = [w.receipt(p, d) for p, d in yes]

    # D4: both reveals. Carol says yes, withdraws, then Dan says yes.
    morning(w, [alice, bob, carol, dan], d0 + 4)
    out["d4"] = {p.name: p.items[-1][1] for p in c.values()}
    w.send_answers(carol)
    w.advance(HOUR)
    out["withdrawal"] = w.withdraw(carol)
    w.send_answers(dan)
    w.advance(2 * HOUR)
    out["withdrawal_receipt"] = w.receipt(carol, out["withdrawal"])
    pair = next(p for p in w.writer().ledger.pairs.values() if dan.subject in (p.a, p.b))
    out["carol_dan_state"] = pair.state

    # D5: the upgrade. The batch of D5 is the same bytes before and after.
    morning(w, [alice, bob, dan], d0 + 5)
    out["carol_d5"] = w.read_slots(carol)
    relay_b = w.nodes["B"].relay
    before = {a: v for a, v in relay_b.slots.items() if v[1] == d0 + 5}
    old = w.writer()
    new = w.instance("two", w.rel2)
    new.register()
    w.publish()
    msg = old.hand_off(new.document, w.rel2)
    new.accept_hand_off(msg)
    old.finish_hand_off()
    w.advance(HOUR)
    out["roles"] = (old.role, new.role)
    w.advance(HOUR)
    assert relay_b.fetch_batch(d0 + 5)  # the new writer serves the same day again
    after = {a: v for a, v in relay_b.slots.items() if v[1] == d0 + 5}
    out["batch_same"] = bool(before) and before == after

    # Carol's pack with her old consent is refused by the tombstone.
    digest = w.upload(carol)
    w.advance(HOUR)
    out["tombstoned"] = w.receipt(carol, digest)

    # D6, D7: Carol's slots by the 48 h rule; the new writer serves the days.
    morning(w, [alice, bob, dan], d0 + 6)
    out["carol_d6"] = w.read_slots(carol)
    morning(w, [alice, bob, dan], d0 + 7)
    out["carol_d7"] = w.read_slots(carol)

    # Dan's copy ends at its expiry (day of delivery + 14).
    for day in range(d0 + 8, d0 + 18):
        morning(w, [alice, bob, dan], day)
    out["dan_items"] = [item for _, item in dan.items]
    return out


def test_planted_pair_gets_one_proposal_each(story: dict) -> None:
    d1 = story["d1"]
    assert d1["Alice Okafor"]["kind"] == d1["Bob Lindqvist"]["kind"] == "proposal"
    assert d1["Alice Okafor"]["id"] != d1["Bob Lindqvist"]["id"]  # unrelated IDs for the two copies
    assert d1["Alice Okafor"]["reasons"] == ["o01", "w01"]  # her own lines only (card a)
    assert (
        d1["Carol Nakamura"] == d1["Dan Petrov"] == {"kind": "empty"}
    )  # the denied pair and non-pairs


def test_lifting_the_deny_is_a_material_change(story: dict) -> None:
    d2 = story["d2"]
    assert d2["Carol Nakamura"]["kind"] == d2["Dan Petrov"]["kind"] == "proposal"
    assert d2["Alice Okafor"] == d2["Bob Lindqvist"] == {"kind": "empty"}  # no second proposal


def test_answers_wait_for_the_fixed_day(story: dict) -> None:
    assert story["early"] == []


def test_crash_before_epoch_loses_both_or_neither(story: dict) -> None:
    assert story["reveals_before_crash"] == 1
    assert story["reveals_after_crash"] == 0
    assert story["receipts_lost"] == [None, None]  # no receipt of the lost work
    assert [r["status"] for r in story["receipts_resent"]] == ["accepted", "accepted"]


def test_both_reveals_go_out_with_card_and_roster_node(story: dict) -> None:
    w, alice, bob = story["world"], story["alice"], story["bob"]
    a, b = story["d4"]["Alice Okafor"], story["d4"]["Bob Lindqvist"]
    assert a["kind"] == b["kind"] == "reveal"
    assert a["card"] == bob.card and b["card"] == alice.card
    assert a["peer"] == bob.subject and b["peer"] == alice.subject
    node_b = w.nodes["B"].record
    assert a["node"] == {k: node_b[k] for k in ("affiliation", "id", "ror")}
    assert a["known"] is False


def test_withdrawal_after_yes_gives_no_reveal(story: dict) -> None:
    assert story["withdrawal_receipt"]["status"] == "accepted"
    assert story["carol_dan_state"] != "revealed"
    dan_kinds = [i["kind"] for i in story["dan_items"]]
    assert "reveal" not in dan_kinds
    assert dan_kinds.count("ended") == 1  # at the expiry of Dan's copy


def test_old_consent_after_withdrawal_is_tombstoned(story: dict) -> None:
    assert story["tombstoned"]["status"] == "rejected"
    assert story["tombstoned"]["reason"] == "tombstoned"


def test_slots_follow_the_48_hour_rule(story: dict) -> None:
    assert story["carol_d5"] == {"kind": "empty"}  # the withdrawal counts as an upload
    assert story["carol_d6"] == {"kind": "empty"}
    assert story["carol_d7"] is None  # the filler: no slot after 48 hours


def test_upgrade_hands_off_the_line(story: dict) -> None:
    assert story["roles"] == ("retired", "writer")
    assert story["batch_same"]


def test_every_node_visible_message_has_its_fixed_size(story: dict) -> None:
    sizes = {"uploads": m.CLASS_UPLOAD, "known": m.CLASS_KNOWN, "answers": m.CLASS_ANSWER}
    traffic = story["world"].node_traffic()
    for method, path, request, response in traffic:
        parts = path.strip("/").split("/")
        if method == "POST":
            assert len(request) == m.SIZES[sizes[parts[-1]]], path
        elif parts[0] == "enclave" and "receipts" in parts:  # the app side: never a 404
            assert len(response) == m.RECEIPT_SIZE, path
        elif parts[0] == "enclave" and "slots" in parts:
            assert len(response) == m.SLOT_SIZE, path


def test_no_person_bytes_reach_a_node(story: dict) -> None:
    w = story["world"]
    seen = b"".join(b"".join(x[2:]) for x in w.node_traffic())
    for p in w.people.values():
        for secret in p.secrets():
            assert secret not in seen, (p.name, secret)


def test_no_person_bytes_reach_a_peer_before_mutual_yes(story: dict) -> None:
    from anagram.core.canonical import canonical_json

    w = story["world"]
    for p in w.people.values():
        for _, item in p.items:
            if item["kind"] == "reveal":
                continue
            got = canonical_json(item)
            for peer in w.people.values():
                if peer is not p:
                    for secret in peer.secrets():
                        assert secret not in got, (p.name, peer.name, secret)


def run_alice(dan_offer: str) -> list[bytes]:
    """What Alice's app opens on days 1 to 4, when only Dan (whom Alice
    cannot match: Dan denies her node) changes."""
    w = World(answer_day=2)
    c = cast(w, dan_offer)
    d0 = w.t // DAY
    for p in c.values():
        w.upload(p)
    out = []
    for day in range(d0 + 1, d0 + 4):
        morning(w, list(c.values()), day)
        out.append(w.slot_plain(c["alice"], day))
        out.append(b"|".join(sorted(a.encode() for a in w.nodes["A"].relay.slots)))
    return out


def test_non_interference_when_a_hidden_peer_changes() -> None:
    assert run_alice(PHYLO) == run_alice("Stable isotope analysis of ancient cereal grains")


def run_bob(alice_choice: str) -> list[bytes]:
    """What Bob's app opens until his copy expires, when Alice answers
    `no` or `not_now` (Bob says yes)."""
    w = World(answer_day=1)
    c = cast(w)
    alice, bob = c["alice"], c["bob"]
    d0 = w.t // DAY
    for p in c.values():
        w.upload(p)
    out = []
    for day in range(d0 + 1, d0 + 17):
        morning(w, [alice, bob], day)
        if day == d0 + 1:
            alice.client.choose(alice.items[-1][1]["id"], alice_choice)
            bob.client.choose(bob.items[-1][1]["id"], "yes", bob.card)
        w.send_answers(alice)
        w.send_answers(bob)
        out.append(w.slot_plain(bob, day))
    return out


def test_no_and_not_now_give_the_peer_the_same_trace() -> None:
    no = run_bob("no")
    assert no == run_bob("not_now")
    assert sum(b'"ended"' in x for x in no) == 1
