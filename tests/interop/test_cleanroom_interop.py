"""The clean-room client against the real enclave and node relay.

`tests/interop/cleanroom/` was written from the specs only. Here it runs
against the reference enclave line and two node relays, which
`tests/enclavekit.py` stands up in one process. The clean-room client
talks to them only through public HTTP routes: enclave-messages.md 9
(app -> node, and node -> enclave for the relay checks), network.md 6.6
(the member credential) and the enclave log read API (enclave-trust.md
2.1). Only the member session comes from the test network: device sign-in
(identity.md) is out of scope.

Story: 2 nodes, 4 people. Alice (node A) and Bob (node B) are a planted
pair and both say yes: both reveals, or neither. Carol (A) and Dan (B) are
a second pair: Carol says yes, Dan says no, so neither gets a reveal and
Dan gets `ended` at the expiry of his copy. Carol then withdraws. Negative
cases: a replayed node request, a tampered pack, envelopes for an unknown
intake key and a stale attestation, a document of an unauthorised line.
"""

from __future__ import annotations

import hashlib
import os

import pytest
from cleanroom import messages as m
from cleanroom.client import App, Trust
from cleanroom.core import Refused, Signer, cjson, day_of, fmt_time, parse_canonical, parse_time
from cleanroom.harness import LogAdapter, pins_from
from enclavekit import HOUR, World, seed

CRYO = "Single-particle cryo-EM map refinement of membrane proteins"
MD = "Molecular dynamics simulations of membrane transporters"
FIELD = "Field surveys of alpine plant pollinators"
PHYLO = "Bayesian phylogenetics of beetle radiations"


def _line(lid: str, text: str) -> dict:
    cls = "method" if lid.startswith("o") else "skill"
    return {
        "class": cls,
        "concepts": [],
        "id": lid,
        "scope": "both",
        "text": text,
        "types": ["research_fit"],
    }


def lines(offer: str, want: str) -> dict:
    return {"offers": [_line("o01", offer)], "wants": [_line("w01", want)]}


class Net:
    """The running network, seen by the clean-room client."""

    def __init__(self) -> None:
        self.w = World(answer_day=2)
        self.pins = pins_from(self.w.trust.roots)
        self.reader = LogAdapter(self.w.log_http)
        self.node_keys = {label: Signer(seed(f"node {label}")) for label in ("A", "B")}

    def person(self, name: str, label: str) -> App:
        n = self.w.nodes[label]
        email = f"{name.split()[0].lower()}@{n.record['domain']}"
        card = {
            "email": email,
            "institution": n.record["affiliation"],
            "lab": None,
            "name": name,
            "orcid": None,
        }
        pid = "pid:" + hashlib.sha256(name.encode()).hexdigest()[:32]
        session, device = self.w.member_session(label, name, pid, email)
        return App(
            subject=Signer(hashlib.sha256(f"cleanroom person {name}".encode()).digest()),
            http=n.http,
            trust=Trust(self.pins, self.reader, self.w.now),
            node=n.id,
            session=session,
            device=device.public_bytes().hex(),
            pid=pid,
            email=email,
            card=card,
            clock=self.w.now,
            reply=hashlib.sha256(f"cleanroom reply {name}".encode()).digest(),
        )

    def relay(self, label: str, method: str, path: str, body: bytes = b"", **kw):
        """A node -> enclave request signed by the clean-room node code."""
        node = self.node_keys[label]
        headers = m.node_headers(
            node, m.node_id(node.public), self.pins.log_key.name, method, path, body,
            kw.pop("time", self.w.now()), kw.pop("nonce", None),
        )  # fmt: skip
        headers.update(kw.pop("headers", {}))
        return self.w.enclave_http.request(method, path, content=body or None, headers=headers)


@pytest.fixture(scope="module")
def story() -> dict:  # noqa: PLR0915
    net = Net()
    w = net.w
    alice, bob = net.person("Alice Okafor", "A"), net.person("Bob Lindqvist", "B")
    carol, dan = net.person("Carol Nakamura", "A"), net.person("Dan Petrov", "B")
    cast = {
        alice: lines(CRYO, MD),
        bob: lines(MD, CRYO),
        carol: lines(FIELD, PHYLO),
        dan: lines(PHYLO, FIELD),
    }
    out: dict = {"net": net, "alice": alice, "bob": bob, "carol": carol, "dan": dan}
    d0 = day_of(w.t)
    out["d0"] = d0

    # D0: every app uploads. Before the next cosigned epoch the receipt is a filler.
    first = {p: p.upload(cast[p]) for p in cast}
    out["receipt_before_epoch"] = alice.receipt(first[alice])
    out["filler_bytes"] = alice.http.get(f"/enclave/receipts/{first[alice]}").content
    out["filler_digest"] = first[alice]
    w.advance(HOUR)
    out["first_receipts"] = {p.card["name"]: p.receipt(first[p]) for p in cast}

    # Replay at the app level: a second pack on the same day (new response key).
    second = alice.upload(cast[alice])
    w.advance(HOUR)
    out["second_pack_receipt"] = alice.receipt(second)

    items: dict[str, list[tuple[int, dict | None]]] = {p.card["name"]: [] for p in cast}

    def morning(day: int, who: list[App]) -> None:
        w.to_day(d0 + day)
        for p in who:
            p.upload(cast[p])
        for p in cast:
            it = p.slot()
            items[p.card["name"]].append((day, it))
            if it and it["kind"] == "proposal" and it["id"] not in p.choices:
                p.choose(it["id"], "no" if p is dan else "yes")

    everyone = list(cast)
    morning(1, everyone)
    morning(2, everyone)
    out["early_answers"] = [p.send_due() for p in everyone]  # not yet due (answer_day = 2)
    morning(3, everyone)
    out["answers"] = {p.card["name"]: p.send_due() for p in everyone}
    w.advance(HOUR)
    out["answer_receipts"] = {
        p.card["name"]: [p.receipt(d) for d in out["answers"][p.card["name"]]] for p in everyone
    }

    # Replay of the same answer bytes: same receipt. A new answer: already_answered.
    a_digest = out["answers"]["Alice Okafor"][0]
    alice.resend(a_digest)
    w.advance(HOUR)
    out["resent_receipt"] = alice.http.get(f"/enclave/receipts/{a_digest}").content
    out["first_answer_receipt"] = alice.receipts[a_digest]
    pid = next(iter(alice.proposals))
    doc = m.answer(alice.subject, pid, "no", None, w.now())
    out["second_answer"] = alice._send(m.ANSWER, cjson(doc), "/enclave/answers")
    w.advance(HOUR)
    out["second_answer_receipt"] = alice.receipt(out["second_answer"])

    # D4: both reveals go out.
    morning(4, everyone)
    # Carol withdraws (her "yes" is open; Dan said "no").
    out["withdrawal"] = carol.withdraw()
    w.advance(HOUR)
    out["withdrawal_receipt"] = carol.receipt(out["withdrawal"])
    # Carol uploads nothing more. The day after: a slot; two days later: none.
    rest = [alice, bob, dan]
    out["fillers_before"] = {p.card["name"]: len(p.fillers) for p in everyone}
    out["filler_receipts"] = []
    for day in range(5, 20):
        morning(day, rest)
        # Yesterday's filler receipts (the node keeps a receipt 48 hours).
        out["filler_receipts"] += [
            p.receipt(d) for p in rest for d in p.fillers if d not in p.receipts
        ]
        for p in rest:
            p.send_due()
    out["fillers_after"] = {p.card["name"]: len(p.fillers) for p in rest}
    out["items"] = items

    # Carol comes back: old consent is tombstoned; a new consent is accepted.
    old = carol.pack_body(cast[carol])
    out["old_consent"] = carol._send(m.UPLOAD, old, "/enclave/uploads")
    w.advance(HOUR)
    out["old_consent_receipt"] = carol.receipt(out["old_consent"])
    w.to_day(d0 + 21)
    carol.approved_at = w.now()
    out["new_consent"] = carol.upload(cast[carol])
    w.advance(HOUR)
    out["new_consent_receipt"] = carol.receipt(out["new_consent"])
    return out


def names(items: list[tuple[int, dict | None]]) -> list[tuple[int, str | None]]:
    return [(d, it["kind"] if it else None) for d, it in items]


# ---- the happy path ---------------------------------------------------------------


def test_every_first_upload_is_accepted(story: dict) -> None:
    assert all(r and r["status"] == "accepted" for r in story["first_receipts"].values())


def test_receipt_is_a_filler_before_the_cosigned_epoch(story: dict) -> None:
    assert story["receipt_before_epoch"] is None
    expect = m.receipt_filler(seed("slots A"), story["filler_digest"])
    assert story["filler_bytes"] == expect  # the spec's filler, byte for byte


def test_second_pack_in_a_day_is_rate_limited(story: dict) -> None:
    r = story["second_pack_receipt"]
    assert r is not None and r["reason"] == "rate_limited"


def test_planted_pair_gets_one_proposal_each_on_day_one(story: dict) -> None:
    for name in ("Alice Okafor", "Bob Lindqvist"):
        assert names(story["items"][name])[0] == (1, "proposal")


def test_answers_wait_for_the_fixed_day(story: dict) -> None:
    assert story["early_answers"] == [[], [], [], []]
    assert all(len(v) == 1 for v in story["answers"].values())


def test_fillers_go_at_the_other_checkpoints(story: dict) -> None:
    """5.3, 5.4: one object at each of the three checkpoints; after the
    answer at the first one, the second and the third get fillers, and
    each filler gets an `accepted` receipt like an answer."""
    assert set(story["fillers_before"].values()) == {0}
    assert set(story["fillers_after"].values()) == {2}
    rs = story["filler_receipts"]
    assert rs and all(r and r["status"] == "accepted" for r in rs)


def test_every_answer_is_accepted(story: dict) -> None:
    for name, rs in story["answer_receipts"].items():
        assert [r and r["status"] for r in rs] == ["accepted"], name


def test_both_reveals_go_out_with_the_peer_card(story: dict) -> None:
    alice, bob = story["alice"], story["bob"]
    a = dict(story["items"]["Alice Okafor"])[4]
    b = dict(story["items"]["Bob Lindqvist"])[4]
    assert a["kind"] == b["kind"] == "reveal"
    assert a["card"] == bob.card and b["card"] == alice.card
    assert a["peer"] == bob.subject.hex and b["peer"] == alice.subject.hex
    assert a["proposal"] in alice.proposals and b["proposal"] in bob.proposals
    assert a["node"]["id"] == bob.node and b["node"]["id"] == alice.node


def test_yes_and_no_give_neither_a_reveal(story: dict) -> None:
    for name in ("Carol Nakamura", "Dan Petrov"):
        assert "reveal" not in [k for _d, k in names(story["items"][name])], name


def test_dan_gets_ended_at_the_expiry_of_his_copy(story: dict) -> None:
    dan = story["dan"]
    (day, item) = next(iter(dan.proposals.values()))
    expires = day_of(parse_time(item["expires"]))
    ended = [d for d, it in story["items"]["Dan Petrov"] if it and it["kind"] == "ended"]
    assert ended, names(story["items"]["Dan Petrov"])
    # 6.4: queued at the expiry (00:00 of day + 14), never before; the batch
    # of that day was cut at 23:00 the day before, so the next slot carries it.
    assert story["d0"] + ended[0] in (expires, expires + 1)


# ---- replay -------------------------------------------------------------------------


def test_same_answer_bytes_get_the_same_receipt(story: dict) -> None:
    alice = story["alice"]
    digest = story["answers"]["Alice Okafor"][0]
    doc = m.open_receipt(alice.sent[digest], story["resent_receipt"], alice.trust_outputs())
    assert doc == story["first_answer_receipt"]


def test_a_second_answer_is_already_answered(story: dict) -> None:
    assert story["second_answer_receipt"]["reason"] == "already_answered"


def test_replayed_node_request_is_refused(story: dict) -> None:
    net = story["net"]
    body = os.urandom(m.SIZE[m.UPLOAD])
    nonce = os.urandom(16).hex()
    t = net.w.now()
    first = net.relay("A", "POST", "/v1/relay/uploads", body, nonce=nonce, time=t)
    again = net.relay("A", "POST", "/v1/relay/uploads", body, nonce=nonce, time=t)
    assert (first.status_code, again.status_code) == (202, 403)


def test_two_equal_gets_with_fresh_nonces_both_pass(story: dict) -> None:
    net = story["net"]
    a = net.relay("B", "GET", "/v1/attestation")
    b = net.relay("B", "GET", "/v1/attestation")
    assert (a.status_code, b.status_code) == (200, 200)
    parse_canonical(a.content)  # the bundle is one canonical JSON document (3.7)


@pytest.mark.parametrize(
    "case",
    ["wrong_audience", "time_301s_old", "unknown_node", "bad_signature"],
)
def test_bad_node_request_is_refused(story: dict, case: str) -> None:
    net = story["net"]
    w = net.w
    path = "/v1/attestation"
    if case == "wrong_audience":
        k = net.node_keys["A"]
        h = m.node_headers(k, m.node_id(k.public), "roster.example/x", "GET", path, b"", w.now())
        r = w.enclave_http.get(path, headers=h)
    elif case == "time_301s_old":
        r = net.relay("A", "GET", path, time=w.now() - 301)
    elif case == "unknown_node":
        k = Signer(os.urandom(32))
        h = m.node_headers(k, m.node_id(k.public), net.pins.log_key.name, "GET", path, b"", w.now())
        r = w.enclave_http.get(path, headers=h)
    else:
        r = net.relay("A", "GET", path, headers={"Anagram-Signature": "00" * 64})
    assert r.status_code == 403


# ---- tampered, unauthorised, wrong target ---------------------------------------------


def _receipt_for(story: dict, app: App, s: m.Sealed) -> dict | None:
    app.post("/enclave/uploads" if s.request[4] == m.UPLOAD else "/enclave/answers", s)
    story["net"].w.advance(HOUR)
    return app.receipt(s.digest)


def test_tampered_pack_is_bad_signature(story: dict) -> None:
    bob = story["bob"]
    doc = parse_canonical(bob.pack_body(lines(MD, CRYO), version=bob.version + 1))
    doc["lines"]["offers"][0]["text"] = "Something the person never approved"
    t = bob.refresh()
    s = m.seal_request(m.UPLOAD, cjson(doc), t.digest, t.intake)
    assert _receipt_for(story, bob, s)["reason"] == "bad_signature"


def test_tampered_envelope_is_bad_envelope(story: dict) -> None:
    bob = story["bob"]
    t = bob.refresh()
    s = m.seal_request(m.UPLOAD, b"{}", t.digest, t.intake)
    s.request = s.request[:-1] + bytes([s.request[-1] ^ 1])
    s.digest = m.request_digest(s.request)
    assert _receipt_for(story, bob, s)["reason"] == "bad_envelope"


def test_bad_magic_gets_a_bad_envelope_receipt(story: dict) -> None:
    bob = story["bob"]
    t = bob.refresh()
    s = m.seal_request(m.UPLOAD, b"{}", t.digest, t.intake)
    s.request = b"XXXX" + s.request[4:]
    s.digest = m.request_digest(s.request)
    assert _receipt_for(story, bob, s)["reason"] == "bad_envelope"


def test_extra_field_is_bad_message(story: dict) -> None:
    bob = story["bob"]
    doc = parse_canonical(bob.pack_body(lines(MD, CRYO), version=bob.version + 1))
    doc["extra"] = 1
    doc = bob.subject.sign_doc("anagram/v1/pack/sign", doc)
    t = bob.refresh()
    s = m.seal_request(m.UPLOAD, cjson(doc), t.digest, t.intake)
    assert _receipt_for(story, bob, s)["reason"] == "bad_message"


def test_unknown_intake_key_is_refused(story: dict) -> None:
    bob = story["bob"]
    t = bob.refresh()
    s = m.seal_request(m.UPLOAD, b"{}", t.digest, os.urandom(32))
    assert _receipt_for(story, bob, s)["reason"] == "unknown_instance_key"


def test_stale_attestation_is_refused(story: dict) -> None:
    bob = story["bob"]
    t = bob.refresh()
    s = m.seal_request(m.UPLOAD, b"{}", os.urandom(32).hex(), t.intake)
    assert _receipt_for(story, bob, s)["reason"] == "stale_attestation"


def test_unauthorised_line_is_refused_by_the_app(story: dict) -> None:
    import enclavekit

    net = story["net"]
    w = net.w
    old = enclavekit.LINE
    enclavekit.LINE = "ab" * 16  # a second line with no enclave_line entry
    try:
        rogue = w.instance("rogue", w.rel)
        rogue.register()
    finally:
        enclavekit.LINE = old
    w.instances.remove(rogue)
    w.publish()
    bob = story["bob"]
    bundle = bob.http.get("/enclave/attestation").json()
    assert all(d["line_id"] != "ab" * 16 for d in bundle["documents"])
    bundle["documents"] = [rogue.document]
    with pytest.raises(Refused) as e:
        bob.trust.check_bundle(bundle, bob.subject.hex)
    assert e.value.code == "line_not_authorised"


def test_wrong_shard_cannot_happen_in_v1(story: dict) -> None:
    """v1 has one shard (n = 1, W4 re-check R4): every subject is in it."""
    from cleanroom.trust import shard

    assert {shard(p.subject.hex, 1) for p in (story["alice"], story["dan"])} == {0}


# ---- withdrawal, tombstone, slots ------------------------------------------------------


def test_withdrawal_is_accepted(story: dict) -> None:
    assert story["withdrawal_receipt"]["status"] == "accepted"


def test_withdrawn_subject_keeps_a_slot_for_48_hours(story: dict) -> None:
    carol = names(story["items"]["Carol Nakamura"])
    by_day = dict(carol)
    assert by_day[5] == "empty"  # the withdrawal was the day's upload (6.5)
    assert by_day[7] is None  # no upload in the 48 hours before the cut: a filler


def test_old_consent_after_withdrawal_is_tombstoned(story: dict) -> None:
    assert story["old_consent_receipt"]["reason"] == "tombstoned"


def test_new_consent_after_withdrawal_is_accepted(story: dict) -> None:
    assert story["new_consent_receipt"]["status"] == "accepted"


def test_unknown_slot_address_gets_the_spec_filler(story: dict) -> None:
    net = story["net"]
    address = os.urandom(32)
    r = net.w.nodes["B"].http.get(f"/enclave/slots/{address.hex()}")
    assert r.status_code == 200 and r.content == m.slot_filler(seed("slots B"), address)


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/enclave/uploads", b"x" * 100),
        ("/enclave/known", b"x" * 65_536),
        ("/enclave/answers", b"x" * 2_049),
    ],
)
def test_node_refuses_a_wrong_length(story: dict, path: str, body: bytes) -> None:
    assert story["alice"].http.post(path, content=body).status_code == 400


@pytest.mark.parametrize("path", ["/enclave/slots/ABCD", "/enclave/receipts/" + "G" * 64])
def test_node_refuses_a_bad_address_form(story: dict, path: str) -> None:
    assert story["alice"].http.get(path).status_code == 400


def test_receipt_times_are_whole_seconds(story: dict) -> None:
    r = story["first_receipts"]["Alice Okafor"]
    assert fmt_time(parse_time(r["time"])) == r["time"]
