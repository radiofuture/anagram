"""The node's credential issuer and relay: who gets a proof, and the state
that must survive a restart (spec/network.md 6.6, enclave-messages.md
6.3)."""

from __future__ import annotations

import threading

from enclavekit import World, line

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke
from anagram.core.jsontable import JsonTable
from anagram.core.shared_db import SharedDB
from anagram.network.formats import enclave as m
from anagram.network.formats.roster import credential_request as make_request
from anagram.network.formats.strict import DAY
from anagram.network.matching.node.credentials import CredentialIssuer, IssueRefused
from anagram.network.matching.node.enclave_relay import SLOT_DAYS, EnclaveRelay

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
FIELD = "Field surveys of alpine plant pollinators"


def lines(offer: str, want: str) -> dict:
    return {"offers": [line("o01", offer)], "wants": [line("w01", want)]}


def credential_request(w: World, p, device, nonce: str) -> bytes:
    return canonical_json(make_request(p.key, device.public_bytes().hex(), p.node.id, nonce, w.t))


def test_only_the_owner_gets_the_proof_of_a_credential() -> None:
    """H1: the proof holds the salt and index of the join entry, so a proof
    for another member's credential is `404`, as for an unknown hash."""
    w = World()
    alice = w.person("Alice Okafor", "A", lines(CRYO, MD))
    carol = w.person("Carol Nakamura", "A", lines(MD, CRYO))
    token_a, device_a = w.member_session("A", alice.name, alice.pid, alice.email)
    token_c, _ = w.member_session("A", carol.name, carol.pid, carol.email)
    http = alice.node.http
    got = http.post(
        "/net/credential",
        content=credential_request(w, alice, device_a, "71" * 16),
        headers={"Authorization": f"Bearer {token_a}"},
    ).json()
    w.publish()
    path = f"/net/credential/{got['hash']}/proof"
    assert http.get(path, headers={"Authorization": f"Bearer {token_a}"}).status_code == 200
    stranger = http.get(path, headers={"Authorization": f"Bearer {token_c}"})
    unknown = http.get(
        f"/net/credential/{'0' * 64}/proof", headers={"Authorization": f"Bearer {token_c}"}
    )
    assert stranger.status_code == unknown.status_code == 404
    assert stranger.content == unknown.content


def test_nonces_and_daily_counts_survive_a_restart_and_are_pruned(tmp_path) -> None:
    """M9: a restart of the node does not reset the nonce check or the daily
    limit; old nonces and the counts of past days leave the tables."""
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    _, device = w.member_session("A", p.name, p.pid, p.email)
    member = next(iter(p.node.sessions.values()))
    db = SharedDB(tmp_path / "credentials.sqlite")

    def issuer() -> CredentialIssuer:
        old = p.node.issuer
        return CredentialIssuer(
            old.node,
            old.key,
            old.network,
            old.log,
            w.now,
            seen=JsonTable(db, "nonces"),
            issued=JsonTable(db, "issued"),
        )

    first = issuer()
    first.issue(credential_request(w, p, device, "81" * 16), member)
    restarted = issuer()
    try:
        restarted.issue(credential_request(w, p, device, "81" * 16), member)
    except IssueRefused as exc:
        assert exc.status == 400 and "nonce" in str(exc)
    else:
        raise AssertionError("a nonce seen before the restart was accepted")
    assert sum(restarted.issued.values()) == 1
    w.advance(DAY)
    restarted.issue(credential_request(w, p, device, "82" * 16), member)
    assert list(restarted.seen) == ["82" * 16]
    assert list(restarted.issued.values()) == [1]


def test_the_relay_keeps_slots_relayed_digests_and_fillers_across_a_restart(tmp_path) -> None:
    """H2: a new relay process on the same database serves the same slots,
    asks the enclave for the receipts of digests sent before the restart,
    and gives the same fillers."""
    w = World()
    alice = w.person("Alice Okafor", "A", lines(CRYO, MD))
    bob = w.person("Bob Lindqvist", "B", lines(MD, CRYO))
    carol = w.person("Carol Nakamura", "A", lines(FIELD, CRYO))
    db = SharedDB(tmp_path / "relay.sqlite")
    old = alice.node.relay

    def relay() -> EnclaveRelay:
        return EnclaveRelay.persistent(db, old.node, old.key, old.audience, old.link, w.now)

    first = relay()
    target = alice.client.refresh()
    raw = m.seal_request(
        m.CLASS_UPLOAD, target.digest, target.intake, hpke.public_bytes(hpke.generate()), b"{}"
    )
    first.forward("uploads", raw)
    digest = m.request_digest(raw).hex()
    for p in (alice, bob, carol):
        w.upload(p)
    w.to_day(w.t // DAY + 1)
    first.tick()
    address = m.slot_address(w.t // DAY, alice.client.reply_key).hex()
    unknown = "11" * 32
    slot, filler = first.slot(address), first.slot(unknown)
    assert slot == old.slot(address) != filler
    second = relay()
    assert second.slot(address) == slot and second.slot(unknown) == filler
    assert second.slot_secret == first.slot_secret
    receipt = second.receipt(digest)
    assert receipt != m.receipt_filler(second.slot_secret, bytes.fromhex(digest))


def test_the_relay_timer_and_requests_share_one_lock() -> None:
    """H2: `expire` in the timer thread and requests in other threads do not
    break each other (no `dictionary changed size during iteration`)."""
    w = World()
    relay = w.person("Alice Okafor", "A", lines(CRYO, MD)).node.relay
    stop = threading.Event()
    errors: list[BaseException] = []

    def requests() -> None:
        n = 0
        while not stop.is_set():
            n += 1
            with relay._lock:  # noqa: SLF001 - the test writes as `fetch_batch` does
                relay.slots[f"{n:064x}"] = ["00", w.t // DAY - SLOT_DAYS]
            try:
                relay.slot(f"{n:064x}")
            except BaseException as exc:  # noqa: BLE001 - the test collects every failure
                errors.append(exc)

    t = threading.Thread(target=requests)
    t.start()
    try:
        for _ in range(200):
            relay.expire()
    finally:
        stop.set()
        t.join()
    assert not errors
