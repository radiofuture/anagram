"""Vectors for spec/enclave-messages.md (`spec/vectors/enclave-messages.json`)."""

from __future__ import annotations

import hashlib
from typing import Any

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats.strict import DAY, Refused, fmt_time, pad
from anagram.network.matching.enclave.ledger import (
    ANSWER_DAY,
    Copy,
    Ledger,
    Pair,
    answer_plan,
    cut,
)
from anagram.vectors.net import slots as slot_model
from anagram.vectors.net.build_pack import ALICE_EMAIL, NODE_A, NODE_B
from anagram.vectors.net.fixtures import (
    ATTESTATION,
    DAY0,
    T0,
    Reuse,
    b64,
    ed,
    seed_labels,
    unb64,
    x25519,
    xpub,
)

PROPOSAL = hashlib.sha256(b"anagram net vector: proposal id").hexdigest()[:32]
CARD = {
    "email": ALICE_EMAIL.split("@")[0] + "@lab-a.example.org",
    "institution": "Example University",
    "lab": "Chen Lab",
    "name": "Alice Chen",
    "orcid": None,
}


def _open_upload(intake: Any) -> Any:
    pub = hpke.public_bytes(intake)

    def fn(priv: Any, raw: bytes) -> bytes:
        return m.open_request(raw, {pub: priv}, {pub: ATTESTATION})[1]

    return fn


def sealed_request(reuse: Reuse, label: str, cls: int, body: bytes, response: str) -> dict:
    intake = x25519("enclave intake")
    pub = hpke.public_bytes(intake)
    resp = xpub(response)
    raw = reuse.sealed(
        label,
        intake,
        _open_upload(intake),
        body,
        lambda: m.seal_request(cls, ATTESTATION, pub, resp, body),
    )
    return {
        "class": cls,
        "size": len(raw),
        "header_hex": raw[: m.HEADER].hex(),
        "info_hex": m.request_info(raw[: m.HEADER]).hex(),
        "sealed_b64": b64(raw),
        "request_digest": m.request_digest(raw).hex(),
        "response_key": resp.hex(),
        "response_seed_label": response,
        "body": body.decode("utf-8"),
    }


def sealed_receipt(reuse: Reuse, label: str, doc: dict, digest: bytes, response: str) -> dict:
    priv = x25519(response)
    out_keys = {ed("enclave output").public_bytes().hex()}
    expected = canonical_json(doc)
    raw = reuse.sealed(
        label,
        priv,
        lambda p, r: canonical_json(m.open_receipt(p, digest, r, out_keys)),
        expected,
        lambda: m.seal_receipt(hpke.public_bytes(priv), digest, doc),
    )
    return {
        "doc": doc,
        "request_digest": digest.hex(),
        "response_seed_label": response,
        "sealed_b64": b64(raw),
        "size": len(raw),
    }


def sealed_slot(reuse: Reuse, label: str, item: dict, day: int) -> dict:
    priv = x25519("reply alice")
    out_keys = {ed("enclave output").public_bytes().hex()}
    doc = m.slot_doc(day, item, ed("enclave output"))
    raw = reuse.sealed(
        label,
        priv,
        lambda p, r: canonical_json(m.open_slot(p, day, r, out_keys)),
        canonical_json(doc),
        lambda: m.seal_slot(hpke.public_bytes(priv), day, doc),
    )
    return {
        "address": m.slot_address(day, xpub("reply alice")).hex(),
        "day": day,
        "doc": doc,
        "sealed_b64": b64(raw),
        "size": len(raw),
    }


def plan_json(made: int, answer_day: int) -> dict:
    checkpoints, expires = answer_plan(made, answer_day)
    return {
        "answer_day": answer_day,
        "made": fmt_time(made),
        "checkpoints": [fmt_time(d * DAY) for d in checkpoints],
        "expires": fmt_time(expires),
    }


def answer_plans() -> list[dict]:
    """The checkpoints and the expiry of a proposal (section 5.3): a
    sweep at the cut of day D gives m = D; the copies share the plan."""
    d = DAY0 + 1
    return [
        plan_json(cut(d), ANSWER_DAY),
        plan_json(cut(d) + 1_800, ANSWER_DAY),
        plan_json(d * DAY + 12 * 3_600, ANSWER_DAY),
        plan_json(cut(d), 2),
    ]


def items() -> dict[str, dict]:
    plan = plan_json(cut(DAY0 + 1), ANSWER_DAY)
    return {
        "empty": {"kind": "empty"},
        "proposal": {
            "checkpoints": plan["checkpoints"],
            "expires": plan["expires"],
            "id": PROPOSAL,
            "kind": "proposal",
            "pack_version": 7,
            "protocol": "anagram.fit.method_help.v1",
            "reasons": ["w01"],
            "type": "method_help",
        },
        "reveal": {
            "card": {
                **CARD,
                "email": "bob@lab-b.example.org",
                "lab": None,
                "name": "Bob Okafor",
                "orcid": "0000-0002-1825-0097",
            },
            "kind": "reveal",
            "known": False,
            "node": {
                "affiliation": "Okafor Group, Sample Institute",
                "id": NODE_B,
                "ror": None,
            },
            "peer": ed("bob").public_bytes().hex(),
            "proposal": PROPOSAL,
            "type": "method_help",
        },
        "ended": {"kind": "ended", "proposal": PROPOSAL},
    }


def intake_script() -> list[dict]:
    """Steps of the reference model of section 8 (subject alice), with outcomes."""
    s = ed("alice").public_bytes().hex()
    t = T0
    steps = [
        ("pack", {"version": 7, "created": t, "approved_at": t - 10 * DAY}, t),
        ("pack", {"version": 8, "created": t + 60, "approved_at": t - 10 * DAY}, t + 120),
        ("pack", {"version": 7, "created": t + DAY, "approved_at": t - 10 * DAY}, t + DAY),
        ("pack", {"version": 8, "created": t + DAY, "approved_at": t - 10 * DAY}, t + DAY + 60),
        ("answer", {"proposal": PROPOSAL}, t + DAY + 120),
        ("answer", {"proposal": PROPOSAL}, t + DAY + 180),
        ("answer", {"proposal": "00" * 16}, t + DAY + 240),
        ("known", {"version": 1, "created": t + DAY}, t + DAY + 300),
        ("known", {"version": 2, "created": t + 2 * DAY}, t + 2 * DAY),
        ("known", {"version": 2, "created": t + 7 * DAY}, t + 7 * DAY + 300),
        ("cover", {}, t + 7 * DAY + 600),
        ("cover", {}, t + 8 * DAY - 60),
        ("withdraw", {"version": 9}, t + 8 * DAY),
        ("known", {"version": 3, "created": t + 8 * DAY}, t + 8 * DAY + 30),
        # Signed before the withdrawal (a second device), sent after it, inside
        # the 48 hour age limit, so the tombstone decides (pack.md 7.1, 8).
        (
            "pack",
            {"version": 8, "created": t + 8 * DAY - 120, "approved_at": t - 10 * DAY},
            t + 8 * DAY + 60,
        ),
        ("pack", {"version": 10, "created": t + 9 * DAY, "approved_at": t - 10 * DAY}, t + 9 * DAY),
        (
            "pack",
            {"version": 10, "created": t + 9 * DAY, "approved_at": t + 9 * DAY},
            t + 9 * DAY + 60,
        ),
    ]
    state = Ledger()
    peer = ed("bob").public_bytes().hex()
    state.pairs["pair"] = Pair(s, peer, "method_help", {s: PROPOSAL}, t)
    state.proposals[PROPOSAL] = Copy(s, "pair", "method_help", [], 1, t, DAY0, t + 15 * DAY)
    out = []
    for op, args, now in steps:
        try:
            result = "accepted: " + _step(state, s, op, args, now)
        except Refused as exc:
            result = exc.code
        out.append({"op": op, "args": args, "now": now, "expect": result})
    return out


def _step(state: Ledger, s: str, op: str, a: dict, now: int) -> str:
    """One step on the enclave's own ledger (the state checks of section 8)."""
    reply = xpub("reply alice").hex()
    if op == "pack":
        state.check_pack(s, a["version"], a["created"], a["approved_at"], now)
        pack = {
            "expires": fmt_time(a["created"] + 30 * DAY),
            "reply_key": reply,
            "version": a["version"],
        }
        state.keep_pack(s, pack, {}, True, NODE_A, now)
        return "kept"
    if op == "answer":
        state.answer(s, a["proposal"], "not_now", None, now)
        return "kept"
    if op == "known":
        kept = state.keep_known(s, a["version"], a["created"], [], now)
        return "kept" if kept else "discarded"
    if op == "cover":
        state.check_cover(s, now)
        state.keep_cover(s, NODE_A, reply, now)
        return "next slot only"
    state.withdraw(s, a["version"], NODE_A, reply, now)
    return "tombstone"


AUDIENCE = "enclave.anagram.example/log"
NODE_NONCE = hashlib.sha256(b"anagram net vector: node request nonce").digest()[:16]


def slot_script() -> list[tuple[str, list]]:
    """Crash and commit cases of the day batch, the queues and the 48 hour
    slot rule (sections 6.5 to 6.8). The last argument of pack, cover and
    withdraw is the time of acceptance."""
    d = DAY0 + 1

    def at(day: int, hour: float) -> int:
        return day * DAY + int(hour * 3_600)

    return [
        ("pack", ["alice", NODE_A, "ra", at(d - 1, 10)]),
        ("pack", ["bob", NODE_B, "rb", at(d - 1, 11)]),
        ("cover", ["carol", NODE_A, "rc", at(d - 1, 12)]),
        ("request", ["upload of alice"]),
        ("receipt", ["upload of alice"]),
        ("reveal", ["alice", "bob"]),
        ("epoch", []),
        ("receipt", ["upload of alice"]),
        ("cosign", []),
        ("receipt", ["upload of alice"]),
        ("make_batch", [d]),
        ("serve", [d, NODE_A]),
        ("crash", []),
        ("serve", [d, NODE_A]),
        ("make_batch", [d]),
        ("epoch", []),
        ("serve", [d, NODE_A]),
        ("cosign", []),
        ("serve", [d, NODE_A]),
        ("serve", [d, NODE_B]),
        ("crash", []),
        ("make_batch", [d]),
        ("serve", [d, NODE_A]),
        # A withdrawal after the reveal is queued: both reveals still go out.
        ("pack", ["dave", NODE_A, "rd", at(d, 7)]),
        ("pack", ["erin", NODE_B, "re", at(d, 7.5)]),
        ("reveal", ["dave", "erin"]),
        ("epoch", []),
        ("cosign", []),
        ("withdraw", ["dave", NODE_A, "rd", at(d, 9)]),
        # The day after a withdrawal: henry keeps a slot on days d + 1 and d + 2.
        ("pack", ["henry", NODE_A, "rh", at(d, 6)]),
        ("withdraw", ["henry", NODE_A, "rh", at(d, 8)]),
        ("make_batch", [d + 1]),
        ("epoch", []),
        ("cosign", []),
        ("serve", [d + 1, NODE_A]),
        ("serve", [d + 1, NODE_B]),
        # An upload after the 23:00 cut gives a slot from the batch after.
        ("cover", ["ivy", NODE_A, "ri", at(d, 23.5)]),
        # A crash after the second yes but before its epoch: the yes got no
        # receipt, the app sends it again, and the reveal is decided again.
        ("pack", ["frank", NODE_A, "rf", at(d + 1, 8)]),
        ("pack", ["gina", NODE_B, "rg", at(d + 1, 9)]),
        ("epoch", []),
        ("cosign", []),
        ("reveal", ["frank", "gina"]),
        ("epoch", []),
        ("crash", []),
        ("reveal", ["frank", "gina"]),
        ("epoch", []),
        ("cosign", []),
        ("make_batch", [d + 2]),
        ("epoch", []),
        ("cosign", []),
        ("serve", [d + 2, NODE_A]),
        ("serve", [d + 2, NODE_B]),
    ]


def build(reuse: Reuse, small_pack: dict, known_small: bytes) -> dict:
    alice = ed("alice")
    out_key = ed("enclave output")
    upload = sealed_request(
        reuse, "upload pack", m.CLASS_UPLOAD, canonical_json(small_pack), "response 1"
    )
    digest = bytes.fromhex(upload["request_digest"])
    accepted = m.receipt("accepted", None, digest, T0, out_key)
    other = hashlib.sha256(b"anagram net vector: another request").digest()
    rejected = m.receipt("rejected", "bad_signature", other, T0, out_key)
    yes = m.answer(alice, PROPOSAL, "yes", T0 + DAY, CARD)
    no = m.answer(alice, PROPOSAL, "no", T0 + DAY, None)
    not_now = m.answer(alice, PROPOSAL, "not_now", T0 + DAY, None)
    day = DAY0 + 1
    node_secret = hashlib.sha256(b"anagram net vector: node A slot secret").digest()
    unknown = m.slot_address(day, xpub("nobody"))
    slots = {k: sealed_slot(reuse, f"slot {k}", v, day) for k, v in items().items()}
    batch_slots = {
        bytes.fromhex(slots["empty"]["address"]): _raw(slots["empty"]),
        unknown: m.filler(node_secret, unknown),
    }
    batch = m.slot_batch(day, batch_slots)
    body = canonical_json({"x": 1})
    nonce = NODE_NONCE
    node_payload = m.node_request_payload(
        "node-" + "ab" * 16, AUDIENCE, "POST", "/v1/relay/uploads", T0, body, nonce
    )
    cover = m.cover(alice, "person", small_pack["credential"], xpub("reply alice"), T0 - 300)
    return {
        "description": "Messages between app, node and enclave (spec/enclave-messages.md). "
        "HPKE ciphertexts are random: a verifier opens them with the given private keys "
        "(seeds) and compares the plaintext; it recomputes every other value.",
        "seed_labels": seed_labels(
            alice="alice",
            bob="bob",
            intake="enclave intake",
            output="enclave output",
            reply_alice="reply alice",
        ),
        "keys": {
            "intake_public": xpub("enclave intake").hex(),
            "intake_seed_label": "enclave intake",
            "output_public": out_key.public_bytes().hex(),
            "attestation_digest": ATTESTATION.hex(),
            "alice": alice.public_bytes().hex(),
            "reply_alice_public": xpub("reply alice").hex(),
        },
        "sizes": {
            "upload": m.SIZES[m.CLASS_UPLOAD],
            "known": m.SIZES[m.CLASS_KNOWN],
            "answer": m.SIZES[m.CLASS_ANSWER],
            "receipt": m.RECEIPT_SIZE,
            "slot": m.SLOT_SIZE,
            "header": m.HEADER,
        },
        "tags": [
            m.TAG_HPKE_REQUEST,
            m.TAG_HPKE_RECEIPT,
            m.TAG_HPKE_SLOT,
            m.TAG_REQUEST,
            m.TAG_SLOT,
            m.TAG_SLOT_FILLER.decode(),
            m.TAG_RECEIPT_FILLER.decode(),
            m.TAG_SIGN_RECEIPT,
            m.TAG_SIGN_SLOT,
            m.TAG_SIGN_ANSWER,
            m.TAG_SIGN_WITHDRAWAL,
            m.TAG_SIGN_COVER,
            m.TAG_SIGN_NODE_REQUEST,
        ],
        "errors": list(m.ERRORS),
        "upload": upload,
        "receipt_accepted": sealed_receipt(
            reuse, "receipt accepted", accepted, digest, "response 1"
        ),
        "receipt_rejected": sealed_receipt(
            reuse, "receipt rejected", rejected, other, "response 2"
        ),
        "answers": {
            "yes": _answer(reuse, "answer yes", yes),
            "no": _answer(reuse, "answer no", no),
            "not_now": _answer(reuse, "answer not_now", not_now),
        },
        "answer_filler": _answer(reuse, "answer filler", m.answer_filler()),
        "answer_plans": answer_plans(),
        "withdrawal": {"doc": m.withdrawal(alice, 9, xpub("reply alice"), T0 + 8 * DAY)},
        "cover": {"doc": cover, "body": canonical_json(cover).decode()},
        "receipt_filler": {
            "node_secret": node_secret.hex(),
            "request_digest": digest.hex(),
            "filler_b64": b64(m.receipt_filler(node_secret, digest)),
        },
        "slot_script": slot_model.run(slot_script()),
        "known_padding": {
            "body_sha256": hashlib.sha256(known_small).hexdigest(),
            "padded_sha256": hashlib.sha256(
                pad(known_small, m.plaintext_size(m.CLASS_KNOWN))
            ).hexdigest(),
            "plaintext_size": m.plaintext_size(m.CLASS_KNOWN),
        },
        "slots": slots,
        "filler": {
            "node_secret": node_secret.hex(),
            "address": unknown.hex(),
            "filler_b64": b64(m.filler(node_secret, unknown)),
        },
        "slot_batch": {
            "day": day,
            "addresses": [a.hex() for a in sorted(batch_slots)],
            "size": len(batch),
            "sha256": hashlib.sha256(batch).hexdigest(),
        },
        "node_request": {
            "audience": AUDIENCE,
            "body_hex": body.hex(),
            "nonce": nonce.hex(),
            "payload": node_payload.decode(),
            "signature": ed("node A").sign(m.TAG_SIGN_NODE_REQUEST, node_payload).hex(),
            "node_key": ed("node A").public_bytes().hex(),
        },
        "intake_script": intake_script(),
        "card_email_check": {
            "email_tag": packs.known_tag(packs.email_id(CARD["email"])).hex(),
        },
    }


def _raw(slot: dict) -> bytes:
    return unb64(slot["sealed_b64"])


def _answer(reuse: Reuse, label: str, doc: dict) -> dict:
    return {
        "doc": doc,
        "sealed": sealed_request(reuse, label, m.CLASS_ANSWER, canonical_json(doc), "response 3"),
    }
