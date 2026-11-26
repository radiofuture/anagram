"""The enclave service, its relay API, the node relay and the simulated log
(enclave/{service,intake,release,http}.py, node/enclave_relay.py,
trust/simulated.py), on the in-process world of enclavekit."""

from __future__ import annotations

import pytest
from enclavekit import HOUR, LINE, World, line

from anagram.network.formats import enclave as m
from anagram.network.formats.strict import DAY, Refused, fmt_time, parse_time
from anagram.network.matching.enclave.slot_release import ReleaseDenied, check_item, check_reveal

TEXT = "Single-particle cryo-EM map refinement of membrane proteins"
OTHER = "Molecular dynamics simulations of membrane transporters"


@pytest.fixture
def world() -> World:
    return World()


def alice(w: World):
    return w.person(
        "Alice Okafor", "A", {"offers": [line("o01", TEXT)], "wants": [line("w01", OTHER)]}
    )


def settled(w: World, p, digest: str) -> dict:
    w.advance(HOUR)
    receipt = w.receipt(p, digest)
    assert receipt is not None
    return receipt


def test_a_pack_is_accepted_and_its_receipt_waits_for_a_cosigned_epoch(world: World) -> None:
    p = alice(world)
    digest = world.upload(p)
    assert world.receipt(p, digest) is None  # the node serves the filler first
    filler = p.node.relay.receipt(digest)
    assert len(filler) == m.RECEIPT_SIZE
    assert settled(world, p, digest)["status"] == "accepted"


def test_a_pack_through_another_node_is_refused(world: World) -> None:
    p = alice(world)
    p.client.node = world.nodes["B"].http  # the credential names node A
    assert settled(world, p, world.upload(p))["reason"] == "bad_credential"


def test_one_pack_a_day(world: World) -> None:
    p = alice(world)
    settled(world, p, world.upload(p))
    assert settled(world, p, world.upload(p))["reason"] == "rate_limited"


def test_a_stale_attestation_is_refused_after_the_document_changes(world: World) -> None:
    p = alice(world)
    p.client.refresh()
    world.advance(13 * HOUR)  # the lease renewal makes a new document
    p.version += 1
    old_target = p.client.target
    digest = p.client.withdraw(p.version)  # sealed to the old document
    assert old_target is p.client.target
    assert settled(world, p, digest)["reason"] == "stale_attestation"


def test_the_relay_refuses_unsigned_and_replayed_requests(world: World) -> None:
    http = world.enclave_http
    assert http.get("/v1/attestation").status_code == 403
    relay = world.nodes["A"].relay
    headers = relay.signed_headers("GET", "/v1/attestation", b"")
    assert http.get("/v1/attestation", headers=headers).status_code == 200
    assert http.get("/v1/attestation", headers=headers).status_code == 403  # replay


def test_equal_requests_in_one_second_are_not_replays(world: World) -> None:
    """Each request has its own nonce; the replay key is (node, nonce)."""
    relay = world.nodes["A"].relay
    first = relay.signed_headers("GET", "/v1/attestation", b"")
    second = relay.signed_headers("GET", "/v1/attestation", b"")
    assert first["Anagram-Time"] == second["Anagram-Time"]
    assert first["Anagram-Nonce"] != second["Anagram-Nonce"]
    for headers in (first, second):
        assert world.enclave_http.get("/v1/attestation", headers=headers).status_code == 200
    assert relay.attestation() == relay.attestation()  # no cache in the node


def test_receipts_go_only_to_the_node_that_relayed(world: World) -> None:
    p = alice(world)
    digest = world.upload(p)
    world.advance(HOUR)
    other = world.nodes["B"].relay
    path = f"/v1/relay/receipts/{digest}"
    headers = other.signed_headers("GET", path, b"")
    assert world.enclave_http.get(path, headers=headers).status_code == 404


def test_the_node_checks_lengths_and_forms(world: World) -> None:
    http = world.nodes["A"].http
    assert http.post("/enclave/uploads", content=b"x" * 100).status_code == 400
    assert http.get("/enclave/slots/XYZ").status_code == 400
    unknown = "ab" * 32
    first = http.get(f"/enclave/slots/{unknown}").content
    assert len(first) == m.SLOT_SIZE and http.get(f"/enclave/slots/{unknown}").content == first


def test_a_batch_waits_for_its_cosigned_epoch(world: World) -> None:
    p = alice(world)
    world.upload(p)
    day = world.t // DAY + 1
    world.t = day * DAY - HOUR + 600  # 23:10, the cut
    world.publish()
    world.writer().tick()  # makes the batch and writes an epoch, not yet cosigned
    path = f"/v1/relay/slots/{day}"
    relay = world.nodes["A"].relay
    assert (
        world.enclave_http.get(path, headers=relay.signed_headers("GET", path, b"")).status_code
        == 503
    )
    world.publish()
    world.t += 1
    raw = world.enclave_http.get(path, headers=relay.signed_headers("GET", path, b"")).content
    got_day, entries = m.read_batch(raw)
    assert got_day == day and len(entries) == 1


def test_a_stale_checkpoint_makes_the_clock_unsafe(world: World) -> None:
    p = alice(world)
    p.client.refresh()
    world.t += 2 * HOUR  # no checkpoint for two hours
    world.writer().tick()
    assert world.writer().ledger.audit.get("clock_unsafe", 0) >= 1


def test_the_log_refuses_an_instance_key_without_its_document(world: World) -> None:
    inst = world.instances[0]
    entry = next(e for e in world.log.entries if e["kind"] == "enclave_instance_key")
    with pytest.raises(Refused, match="bad_entry"):
        world.log.append(entry)
    doc = dict(inst.document, platform_evidence={"report": {}, "signature": "", "signer": ""})
    with pytest.raises(Refused, match="bad_attestation"):
        world.log.append_instance_key(entry, doc)


def test_the_anagram_witnesses_refuse_a_second_line_with_the_same_id(world: World) -> None:
    world.trust.authorise_line(world.rel, LINE)
    with pytest.raises(Refused, match="quorum"):
        world.publish()


def test_a_handoff_to_a_release_that_is_not_a_successor_is_refused(world: World) -> None:
    other = world.trust.release(
        world.rel["descriptor_hashes"],
        {"gpu": False, "image_digest": "sha256:" + "3" * 64},
        {"svn": 3},
        world.t,
        commit="3" * 40,
    )
    world.publish()
    with pytest.raises(Refused):
        world.writer().hand_off(world.instances[0].document, other)
    assert world.writer().ledger.audit  # the refusal is counted


def test_the_release_check_denies_what_is_not_the_recipients(world: World) -> None:
    a = alice(world)
    b = world.person(
        "Bob Lindqvist", "B", {"offers": [line("o01", OTHER)], "wants": [line("w01", TEXT)]}
    )
    c = world.person(
        "Carol Nakamura",
        "A",
        {"offers": [line("o01", "Alpine pollinators")], "wants": [line("w01", "Beetles")]},
    )
    for p in (a, b, c):
        world.upload(p)
    world.to_day(world.t // DAY + 1)
    ledger = world.writer().ledger
    copy_id, mine = next(
        (pid, cp) for pid, cp in ledger.proposals.items() if cp.subject == a.subject
    )
    item = {
        "checkpoints": [fmt_time(d * DAY) for d in ledger.pairs[mine.pair].checkpoints],
        "expires": fmt_time(mine.expires),
        "id": copy_id,
        "kind": "proposal",
        "pack_version": mine.pack_version,
        "protocol": "anagram.fit.research_fit.v1",
        "reasons": list(mine.reasons),
        "type": "research_fit",
    }
    assert check_item(ledger, a.subject, item) == item
    with pytest.raises(ReleaseDenied):
        check_item(ledger, b.subject, item)  # another person's copy
    with pytest.raises(ReleaseDenied):
        check_item(ledger, a.subject, {**item, "reasons": ["o02"]})
    early = [fmt_time(parse_time(t, "t") - DAY) for t in item["checkpoints"]]
    with pytest.raises(ReleaseDenied):
        check_item(ledger, a.subject, {**item, "checkpoints": early})
    reveal = {
        "card": None,
        "kind": "reveal",
        "known": False,
        "node": {},
        "peer": b.subject,
        "proposal": copy_id,
        "type": "research_fit",
    }
    with pytest.raises(ReleaseDenied):
        check_reveal(ledger, mine.pair, a.subject, reveal, world.nodes["B"].record)  # no yes
