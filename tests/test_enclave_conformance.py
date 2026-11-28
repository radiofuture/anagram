"""Conformance fixes of enclave matching, on the in-process world of
enclavekit:

- C1: a control event that removes a member erases the subject at once,
  with a tombstone, and nothing names the subject after it;
- C2: a step-1 failure gets a receipt; every request goes to the writer;
- C3: the node timer keeps a receipt 48 hours and a slot 28 days;
- receipt codes that only vectors tested before: `unsupported_schema`,
  `revoked`, `too_large`;
- the node's `/enclave/*` routes need a member session (401, 403);
- G8: the log read routes and `POST /net/credential`;
- the flaky receipt: a credential check must not depend on the speed of
  the computer (the Biscuit run limits).
"""

from __future__ import annotations

import json
import threading
from datetime import timedelta

import httpx
import pytest
from enclavekit import HOUR, ROSTER, START, World, line

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke
from anagram.core.crypto.signing import SigningKey
from anagram.network.formats import credential as cred
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import credential_request as make_request
from anagram.network.formats.roster import subject_hash
from anagram.network.formats.strict import DAY, Refused, fmt_time
from anagram.network.matching.enclave.ledger import decline_id, tombstone_id
from anagram.network.matching.enclave.state import EPOCH
from anagram.network.matching.hosting.runtime import Ticker
from anagram.network.matching.node.control import ControlChain
from anagram.network.matching.trust.issuance import month_of
from anagram.vectors.net.build_network import POLICY

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
FIELD = "Field surveys of alpine plant pollinators"


def lines(offer: str, want: str) -> dict:
    return {"offers": [line("o01", offer)], "wants": [line("w01", want)]}


def settled(w: World, p, digest: str) -> dict:
    w.advance(HOUR)
    receipt = w.receipt(p, digest)
    assert receipt is not None
    return receipt


def pair(w: World):
    """Alice (node A) and Bob (node B): one proposal each, delivered on day 1.
    Carol (node A) makes the anonymity pool large enough."""
    alice = w.person("Alice Okafor", "A", lines(CRYO, MD))
    bob = w.person("Bob Lindqvist", "B", lines(MD, CRYO))
    carol = w.person("Carol Nakamura", "A", lines(FIELD, CRYO))
    for p in (alice, bob, carol):
        w.upload(p)
    w.to_day(w.t // DAY + 1)
    for p in (alice, bob):
        assert w.read_slots(p)["kind"] == "proposal"
    return alice, bob


# ---- C1: removal by control event (enclave-trust.md 7.1; network.md 8.4, 8.5) ----


def remove(w: World, how: str, p) -> None:
    """Add the control event `how` that removes person `p`."""
    node = p.node
    if how == "node_removed":
        body = {"node": node.id, "reason": "abuse"}
        w.feed.add(ROSTER, "node_removed", body, w.t, w.roster_key)
    elif how == "ban":
        body = {"reason": "abuse", "subject": subject_hash(bytes.fromhex(p.subject))}
        w.feed.add(ROSTER, "ban", body, w.t, w.roster_key)
    elif how == "credential_revoked":
        facts = w.writer().ledger.subjects[p.subject].facts
        digest = cred.credential_hash(cred.unb64url(facts["token"])).hex()
        body = {"credential": digest, "reason": "compromised"}
        w.feed.add(node.id, "credential_revoked", body, w.t, node.key)
    else:  # member_removed, or member_left with a reason
        kind, reason = how.split(":") if ":" in how else (how, "removed")
        body = {"reason": reason, "subject": subject_hash(bytes.fromhex(p.subject))}
        w.feed.add(node.id, kind, body, w.t, node.key)
        if reason != "moved":
            p.join = None  # the node makes a new join entry if the person comes back (6.7)


def traces(w: World, p) -> list[str]:
    """Each value in the snapshot form that is the key of `p` or made from
    it, other than the tombstone (the one exception of 7.1 here: the peer
    gave no "no", so there is no decline record)."""
    state = w.writer().ledger.to_json()
    state["tombstones"].pop(tombstone_id(p.subject), None)
    text = json.dumps(state)
    others = [q.subject for q in w.people.values() if q is not p]
    derived = {
        p.subject,
        p.client.reply_key.hex(),
        p.pid,
        tombstone_id(p.subject),
        subject_hash(bytes.fromhex(p.subject)),
        packs.known_tag(packs.email_id(p.email)).hex(),
        packs.known_tag(packs.person_id(p.subject)).hex(),
        *(decline_id(p.subject, o, kind) for o in others for kind in packs.TYPES),
        *(decline_id(o, p.subject, kind) for o in others for kind in packs.TYPES),
    }
    return sorted(v for v in derived if v in text)


@pytest.mark.parametrize(
    "how",
    ["member_removed", "credential_revoked", "node_removed", "member_left:left", "ban"],
)
def test_a_removal_erases_at_once_and_nothing_names_the_member_after(how: str) -> None:
    w = World()
    alice, bob = pair(w)
    ledger = w.writer().ledger
    alice_copy = next(pid for pid, c in ledger.proposals.items() if c.subject == alice.subject)
    remove(w, how, alice)
    w.advance(HOUR)
    ledger = w.writer().ledger
    s = ledger.subjects[alice.subject]
    assert s.pack is None and s.facts is None and s.known is None
    assert alice_copy not in ledger.proposals
    tomb = ledger.tombstones[tombstone_id(alice.subject)]
    assert tomb["reason"] == "removed" and tomb["version"] == alice.version
    # Bob's delivered copy lives on and ends at its own expiry.
    bob_copies = [c for c in ledger.proposals.values() if c.subject == bob.subject]
    assert len(bob_copies) == 1
    # 20 days later: Bob's copy expired, Alice's slot state ended.
    for _ in range(20):
        w.to_day(w.t // DAY + 1)
        w.read_slots(bob)
    assert "ended" in [item["kind"] for _day, item in bob.items]
    assert traces(w, alice) == []
    assert w.writer().ledger.history == {}


def test_a_member_who_moved_is_dormant_not_erased() -> None:
    """network.md 8.4: `member_left` with `moved` deletes nothing; the pack
    is not used until a credential from another node comes."""
    w = World()
    alice, _bob = pair(w)
    remove(w, "member_left:moved", alice)
    w.advance(HOUR)
    ledger = w.writer().ledger
    assert ledger.subjects[alice.subject].pack is not None
    assert tombstone_id(alice.subject) not in ledger.tombstones


def test_a_removed_member_who_comes_back_is_accepted() -> None:
    """The tombstone refuses only what is older than it (pack.md 8): a later
    credential from the node and a newer pack pass."""
    w = World()
    alice, _bob = pair(w)
    remove(w, "member_removed", alice)
    w.advance(HOUR)
    w.to_day(w.t // DAY + 1)
    assert settled(w, alice, w.upload(alice))["status"] == "accepted"


def test_an_erasure_survives_a_restart() -> None:
    """A restart loads the last cosigned epoch; if that epoch is older than
    the erasure, the pass runs again."""
    w = World()
    alice, _bob = pair(w)
    remove(w, "member_removed", alice)
    writer = w.writer()
    w.publish()
    writer.observe()  # erases in memory; no epoch holds it yet
    assert writer.ledger.subjects[alice.subject].pack is None
    writer.restart()
    assert writer.ledger.subjects[alice.subject].pack is not None
    w.advance(HOUR)
    assert writer.ledger.subjects[alice.subject].pack is None


# ---- C2: receipts for step 1; the writer takes every request ----------------------


def send_raw(p, route: str, raw: bytes, response) -> str:
    digest = m.request_digest(raw).hex()
    p.client.responses[digest] = response
    assert p.node.http.post(f"/enclave/{route}", content=raw).status_code == 202
    return digest


def sealed(p, cls: int, body: bytes, intake: bytes | None = None, digest: bytes | None = None):
    target = p.client.refresh()
    response = hpke.generate()
    raw = m.seal_request(
        cls,
        digest or target.digest,
        intake or target.intake,
        hpke.public_bytes(response),
        body,
    )
    return raw, response


@pytest.mark.parametrize("damage", ["magic", "class"])
def test_a_step_one_failure_gets_a_bad_envelope_receipt(damage: str) -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    raw, response = sealed(p, m.CLASS_UPLOAD, b"{}")
    raw = b"XXXX" + raw[4:] if damage == "magic" else raw[:4] + bytes([m.CLASS_ANSWER]) + raw[5:]
    digest = send_raw(p, "uploads", raw, response)
    assert settled(w, p, digest)["reason"] == "bad_envelope"


def test_a_request_to_a_standby_key_gets_unknown_instance_key_from_the_writer() -> None:
    """enclave-trust.md 3.7: the front end sends each request to the writer;
    a request sealed to another instance's key gets `unknown_instance_key`,
    signed by the writer."""
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    standby = w.instance("standby", w.rel)
    standby.register()
    w.publish()
    raw, response = sealed(
        p,
        m.CLASS_UPLOAD,
        b"{}",
        intake=standby.keys.intake_public,
        digest=standby.keys.attestation_digest(),
    )
    digest = send_raw(p, "uploads", raw, response)
    receipt = settled(w, p, digest)
    assert receipt["reason"] == "unknown_instance_key"
    assert receipt["signer"] == w.writer().keys.output_hex
    assert standby.journal is None and standby.refusals == {}


def test_with_no_writer_the_node_gets_503() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    raw, _response = sealed(p, m.CLASS_UPLOAD, b"{}")
    w.writer().role = "draining"  # between the handoff and its epoch
    relay = p.node.relay
    r = w.enclave_http.post(
        "/v1/relay/uploads",
        content=raw,
        headers=relay.signed_headers("POST", "/v1/relay/uploads", raw),
    )
    assert r.status_code == 503


# ---- receipt codes through the service (enclave-messages.md 10) -------------------


def test_a_schema_that_the_release_does_not_accept_is_unsupported_schema() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    raw, response = sealed(p, m.CLASS_UPLOAD, canonical_json({"schema": "anagram.pack.v9"}))
    digest = send_raw(p, "uploads", raw, response)
    assert settled(w, p, digest)["reason"] == "unsupported_schema"


@pytest.mark.parametrize("schema", [[], {}, ["anagram.pack.v1"]])
@pytest.mark.parametrize("read_kind", [m.upload_kind, m.answer_kind])
def test_a_schema_that_is_not_text_is_unsupported_schema(schema, read_kind) -> None:
    """A list or an object is not hashable, so it is not a key of the schema
    table. The request gets a receipt code, not a TypeError."""
    with pytest.raises(Refused) as err:
        read_kind(canonical_json({"schema": schema}))
    assert err.value.code == "unsupported_schema"


def test_a_pack_over_49152_bytes_is_too_large() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    body = canonical_json({"pad": "x" * 50_000, "schema": "anagram.pack.v1"})
    raw, response = sealed(p, m.CLASS_UPLOAD, body)
    digest = send_raw(p, "uploads", raw, response)
    assert settled(w, p, digest)["reason"] == "too_large"


def test_a_pack_of_a_banned_subject_is_revoked() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    remove(w, "ban", p)
    w.advance(HOUR)
    assert settled(w, p, w.upload(p))["reason"] == "revoked"


# ---- C3: the node timer (enclave-messages.md 4.4, 6.3) -----------------------------


def test_the_node_drops_a_receipt_after_48_hours() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    digest = w.upload(p)
    w.advance(HOUR)
    relay = p.node.relay
    receipt = relay.receipt(digest)
    filler = m.receipt_filler(relay.slot_secret, bytes.fromhex(digest))
    assert receipt != filler and len(receipt) == m.RECEIPT_SIZE
    w.advance(47 * HOUR)
    assert relay.receipt(digest) == receipt  # kept for 48 hours after the fetch
    w.advance(HOUR + 60)
    assert relay.receipt(digest) == filler  # the timer dropped it


def test_the_node_drops_a_slot_after_28_days() -> None:
    """28 days: the answer window (at most 22 days) and a margin."""
    w = World()
    alice, _bob = pair(w)
    day = w.t // DAY
    address = m.slot_address(day, alice.client.reply_key).hex()
    relay = alice.node.relay
    slot = relay.slot(address)
    filler = m.filler(relay.slot_secret, bytes.fromhex(address))
    assert slot != filler
    w.to_day(day + 27)
    assert relay.slot(address) == slot  # kept for 28 days
    w.to_day(day + 28)
    assert relay.slot(address) == filler


# ---- member session on the node routes (enclave-messages.md 9.1) ------------------


ROUTES = [
    ("GET", "/enclave/attestation", b""),
    ("POST", "/enclave/uploads", b"x" * m.SIZES[m.CLASS_UPLOAD]),
    ("POST", "/enclave/known", b"x" * m.SIZES[m.CLASS_KNOWN]),
    ("POST", "/enclave/answers", b"x" * m.SIZES[m.CLASS_ANSWER]),
    ("GET", "/enclave/receipts/" + "ab" * 32, b""),
    ("GET", "/enclave/slots/" + "ab" * 32, b""),
]


@pytest.fixture
def node_with_relay(tmp_path):
    from conftest import make_net

    from anagram.core.crypto.signing import SigningKey
    from anagram.network.matching.node.enclave_relay import EnclaveRelay

    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"the node called the enclave: {request.url}")

    link = httpx.Client(transport=httpx.MockTransport(refuse), base_url="http://enclave.test")
    relay = EnclaveRelay(
        "node-a", SigningKey.generate(), "enclave.test/log", link, lambda: 0, b"\x07" * 32
    )
    return make_net(tmp_path, enclave=relay)


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_the_enclave_routes_need_a_member_session(node_with_relay, method, path, body) -> None:
    net = node_with_relay
    assert net.tc.request(method, path, content=body or None).status_code == 401
    start = net.tc.post(
        "/auth/email/start",
        json={"device_key": "11" * 32, "email": "x@example.org", "nonce": "22" * 16},
    ).json()
    code = net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]
    outsider = net.tc.post(
        "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": code}
    ).json()["session"]["token"]
    headers = {"Authorization": f"Bearer {outsider}"}
    assert net.tc.request(method, path, content=body or None, headers=headers).status_code == 403


# ---- G8: the log read API and the member credential routes -------------------------


def test_the_log_read_routes_give_entries_and_checkpoints() -> None:
    w = World()
    http = w.log_http
    note = http.get("/log/checkpoint").text
    assert note == w.log.checkpoint()
    size = int(note.split("\n")[1])
    got = json.loads(http.get(f"/log/entries?start=0&end={size}").content)["entries"]
    assert got == w.log.read(0, size)
    assert http.get(f"/log/checkpoint/covering/{size - 1}").text == w.log.covering(size - 1)
    assert http.get(f"/log/entries?start=0&end={size + 1}").status_code == 400
    assert http.get(f"/log/checkpoint/covering/{size}").status_code == 404


# ---- C44: new members of each node and month (network.md 6.7) ------------------


def test_the_log_shows_new_members_of_each_node_and_month() -> None:
    """Renewals do not count: Alice's second credential is a renewal."""
    w = World()
    alice = w.person("Alice Okafor", "A", lines(CRYO, MD))
    bob = w.person("Bob Lindqvist", "B", lines(MD, CRYO))
    for p in (alice, alice, bob):
        w.credential(p)
    month = month_of(w.t)
    got = json.loads(w.log_http.get(f"/log/issuance?month={month}").content)
    assert got == {"month": month, "nodes": {alice.node.id: 1, bob.node.id: 1}}
    w.credential(w.person("Carol Nakamura", "A", lines(FIELD, CRYO)))
    got = json.loads(w.log_http.get(f"/log/issuance?month={month}").content)
    assert got["nodes"] == {alice.node.id: 2, bob.node.id: 1}
    assert w.log_http.get("/log/issuance?month=2026-13").status_code == 400


def _limit_policy(w: World, limit: int) -> None:
    policy = {**POLICY, "new_members_per_month": limit}
    w.feed.add(
        ROSTER, "policy_updated", {"effective": fmt_time(w.t), "policy": policy}, w.t, w.roster_key
    )
    w.advance(HOUR)


def test_renewals_never_hit_the_new_member_limit() -> None:
    """The policy allows each node 1 new member a month. Alice renews each
    day and stays accepted; Carol is the second new member of node A and
    gets `issuance_limit`; node B is not affected."""
    w = World()
    _limit_policy(w, 1)
    alice = w.person("Alice Okafor", "A", lines(CRYO, MD))
    for _ in range(5):
        assert settled(w, alice, w.upload(alice))["status"] == "accepted"
        w.to_day(w.t // DAY + 1)
    carol = w.person("Carol Nakamura", "A", lines(FIELD, CRYO))
    bob = w.person("Bob Lindqvist", "B", lines(MD, CRYO))
    assert settled(w, carol, w.upload(carol))["reason"] == "issuance_limit"
    assert settled(w, bob, w.upload(bob))["status"] == "accepted"


def test_a_member_who_comes_back_is_a_new_member_again() -> None:
    """A re-join after a removal needs a new join entry, which counts. The
    join entry from before the removal gives `bad_credential`."""
    w = World()
    _limit_policy(w, 3)  # Alice, Carol (of `pair`) and the re-join of Alice
    alice, _bob = pair(w)
    old = alice.join
    remove(w, "member_removed", alice)
    w.advance(HOUR)
    w.to_day(w.t // DAY + 1)
    alice.join = old
    assert settled(w, alice, w.upload(alice))["reason"] == "bad_credential"
    alice.join = None
    assert settled(w, alice, w.upload(alice))["status"] == "accepted"
    month = month_of(w.t)
    got = json.loads(w.log_http.get(f"/log/issuance?month={month}").content)
    assert got["nodes"][alice.node.id] == 3
    dave = w.person("Dave Mensah", "A", lines(FIELD, MD))
    assert settled(w, dave, w.upload(dave))["reason"] == "issuance_limit"


def test_a_renewal_must_name_its_own_join_entry() -> None:
    """A node cannot mark a new member as a renewal: the proof must name a
    join entry of the same subject (`bad_credential`)."""
    w = World()
    alice = w.person("Alice Okafor", "A", lines(CRYO, MD))
    carol = w.person("Carol Nakamura", "A", lines(FIELD, CRYO))
    assert settled(w, alice, w.upload(alice))["status"] == "accepted"
    carol.join = alice.join
    assert settled(w, carol, w.upload(carol))["reason"] == "bad_credential"


def credential_request(w: World, p, device, nonce: str = "5a" * 16) -> bytes:
    doc = make_request(p.key, device.public_bytes().hex(), p.node.id, nonce, w.t)
    return canonical_json(doc)


def test_a_member_gets_a_credential_and_its_proof() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    token, device = w.member_session("A", p.name, p.pid, p.email)
    auth = {"Authorization": f"Bearer {token}"}
    http = p.node.http
    r = http.post("/net/credential", content=credential_request(w, p, device), headers=auth)
    assert r.status_code == 200
    got = r.json()
    raw = cred.unb64url(got["credential"]["token"])
    assert got["hash"] == cred.credential_hash(raw).hex()
    proof = http.get(f"/net/credential/{got['hash']}/proof", headers=auth).json()["log"]
    assert w.log.read(proof["index"], proof["index"] + 1)[0]["credential_hash"] == got["hash"]
    # The same nonce again is refused; no session is 401; not a member is 403.
    again = http.post("/net/credential", content=credential_request(w, p, device), headers=auth)
    assert again.status_code == 400
    assert http.post("/net/credential", content=b"{}").status_code == 401
    other = credential_request(w, p, device, nonce="6b" * 16)
    stranger = {"Authorization": "Bearer nobody"}
    assert http.post("/net/credential", content=other, headers=stranger).status_code == 403


def test_a_node_writes_a_join_entry_only_for_a_new_member() -> None:
    """Network.md 6.5 and 6.7: the first credential is a join entry; a
    renewal names it and has `member` null; after a removal or exit at the
    node, the next credential is a new join entry."""
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    token, device = w.member_session("A", p.name, p.pid, p.email)
    auth = {"Authorization": f"Bearer {token}"}
    http = p.node.http
    left = {"at": 0}
    p.node.issuer.left = lambda _person_key: left["at"]

    def issue(nonce: str) -> tuple[dict, dict]:
        r = http.post(
            "/net/credential", content=credential_request(w, p, device, nonce), headers=auth
        )
        w.publish()
        proof = http.get(f"/net/credential/{r.json()['hash']}/proof", headers=auth).json()["log"]
        return proof, w.log.read(proof["index"], proof["index"] + 1)[0]

    first, entry = issue("01" * 16)
    assert first["join"]["index"] == first["index"]
    assert entry["member"] == cred.member_commit(p.subject, first["join"]["salt"])
    renewal, entry = issue("02" * 16)
    assert renewal["join"] == first["join"] and entry["member"] is None
    w.advance(HOUR)
    left["at"] = w.t - 60  # the node removed the member, who then came back
    again, entry = issue("03" * 16)
    assert again["join"]["index"] == again["index"] != first["index"]
    assert entry["member"] == cred.member_commit(p.subject, again["join"]["salt"])


def test_the_control_chain_gives_the_last_exit_of_a_person(tmp_path) -> None:
    """The time of the last removal or exit, not `moved` (network.md 6.7)."""
    t = {"now": START}
    chain = ControlChain(
        tmp_path / "control.sqlite", "node-a.example", SigningKey.generate(), lambda: t["now"]
    )
    person = SigningKey.generate().public_bytes().hex()
    subj = subject_hash(bytes.fromhex(person))
    assert chain.left(person) == 0
    chain.add("member_left", {"reason": "moved", "subject": subj})
    assert chain.left(person) == 0
    t["now"] += HOUR
    chain.add("member_removed", {"reason": "removed", "subject": subj})
    assert chain.left(person) == START + HOUR


def test_a_node_issues_at_most_four_credentials_a_day() -> None:
    w = World()
    p = w.person("Alice Okafor", "A", lines(CRYO, MD))
    token, device = w.member_session("A", p.name, p.pid, p.email)
    auth = {"Authorization": f"Bearer {token}"}
    codes = [
        p.node.http.post(
            "/net/credential", content=credential_request(w, p, device, f"{i:032x}"), headers=auth
        ).status_code
        for i in range(5)
    ]
    assert codes == [200, 200, 200, 200, 429]


# ---- C3: the node timer runs from src ----------------------------------------------


def test_the_relay_ticker_runs_the_node_timer() -> None:
    ticked = threading.Event()

    class Relay:
        def tick(self) -> None:
            ticked.set()

    ticker = Ticker("enclave-relay", Relay().tick, every=0.01).start()
    try:
        assert ticked.wait(5)
    finally:
        ticker.stop()


# ---- the flaky receipt: Biscuit run limits (network.md 6.2) ------------------------


def member_biscuit() -> tuple[bytes, str, int]:
    key = SigningKey.from_seed(b"\x01" * 32)
    now = 1_795_608_000
    facts = cred.MemberFacts(
        network="net.anagram.example",
        node="node-" + "ab" * 16,
        subject="cd" * 32,
        kind="person",
        issued=now - 60,
        expires=now - 60 + DAY,
        control_head=0,
        pid="pid:" + "ef" * 16,
        email_tags=("12" * 32,),
    )
    return cred.make_biscuit(facts, key), key.public_bytes().hex(), now


def test_the_credential_check_sets_its_own_run_limits() -> None:
    """The library default stops a run after 1 ms of wall-clock time; on a
    busy computer a pack then got `expired`, or no receipt at all."""
    limits = cred.authorizer_builder(0).limits()
    assert (limits.max_facts, limits.max_iterations) == (cred.RUN_FACTS, cred.RUN_ITERATIONS)
    assert limits.max_time == cred.RUN_TIME >= timedelta(seconds=10)


def test_a_computer_slower_than_the_time_limit_gets_a_code_not_a_crash(monkeypatch) -> None:
    """A zero time limit stands for a computer slower than any limit: the
    check refuses with a receipt code. Before the fix a query raised the
    library's own error there, so the request got no receipt."""
    raw, root, now = member_biscuit()
    assert cred.read_member_biscuit(raw, root, now).subject == "cd" * 32
    monkeypatch.setattr(cred, "RUN_TIME", timedelta(0))
    with pytest.raises(Refused) as exc:
        cred.read_member_biscuit(raw, root, now)
    assert exc.value.code == "bad_credential"


# ---- M4: the epoch index comes from signed time (enclave-trust.md 6.4) -------------


def test_the_epoch_index_comes_from_signed_time_not_the_host_clock() -> None:
    """The host clock leads the witness times. At a time where the host
    clock is past a 10-minute boundary and signed time is not, the writer
    keeps the epoch index of signed time, which the tick compares with."""
    w = World()
    inst = w.writer()
    extra = {"d": 0}
    w.host.clock = lambda: w.t + 250 + extra["d"]
    w.advance(HOUR)
    s = inst.signed
    assert s.seen_at is not None
    offset = s.seen_at - s.lower  # the host clock leads signed time by this
    assert 0 < offset < EPOCH
    signed = s.lower + w.host.clock() - s.seen_at
    target = signed + (EPOCH - offset // 2 - signed % EPOCH) % EPOCH
    extra["d"] = target - signed
    inst.restart()
    assert inst.last_epoch == target // EPOCH
    assert inst.last_epoch != (target + offset) // EPOCH
