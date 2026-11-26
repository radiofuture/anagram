"""The clean-room code against every vector file it covers.

Deterministic values are rebuilt byte for byte (hashes, Ed25519
signatures, fillers, known objects, batches). Random values (HPKE output,
Biscuit tokens) are opened or verified, as the vector files say. Refused
cases must give their code.

Each vector file gives the seed label of its keys (`seed_labels`, and
`response_seed_label` next to each response key; G6 of the conformance
review). The tests derive the private keys from those labels.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cleanroom import messages as m
from cleanroom import trust as t
from cleanroom.core import (
    Refused,
    Signer,
    cjson,
    hpke_open,
    pad,
    parse_canonical,
    parse_time,
    sha256,
    tagged_hash,
    unpad,
    verify_doc,
    x25519_public,
)
from cleanroom.credential import (
    Facts,
    b64url,
    check_join,
    credential_hash,
    join_ranks,
    log_entry,
    member_commit,
    unb64url,
    verify_credential,
)
from cleanroom.pack import (
    Context,
    build_known,
    check_known,
    check_pack,
    email_identifier,
    field_size,
    known_tag,
    known_weekday,
    sign_pack,
    statement_hash,
)

VEC = Path(__file__).resolve().parents[2] / "spec" / "vectors"
PACK = json.loads((VEC / "pack.json").read_text())
MSG = json.loads((VEC / "enclave-messages.json").read_text())
NET = json.loads((VEC / "network.json").read_text())
TRUST = json.loads((VEC / "enclave-trust.json").read_text())


def seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram net vector seed: {label}".encode()).digest()


def ed(label: str) -> Signer:
    return Signer(seed(label))


def b64(s: str) -> bytes:
    return base64.b64decode(s)


# ---- pack.json ---------------------------------------------------------------------


def pack_context(doc: dict | None = None, teasers: bool | None = None) -> Context:
    c = PACK["context"]
    return Context(
        now=parse_time(c["now"]),
        descriptor_set=c["descriptor_set"],
        statement=c["statement"],
        network=c["network"],
        node_keys=c["node_keys"],
        log_roots={int(k): bytes.fromhex(v) for k, v in c["log_roots"].items()},
        schemas=tuple(c["schemas"]),
        teasers_allowed=c["teasers_allowed"] if teasers is None else teasers,
    )


def test_pack_keys_come_from_their_labels() -> None:
    labels = PACK["seed_labels"]["keys"]
    assert {k: ed(labels[k]).hex for k in PACK["keys"]} == PACK["keys"]


def test_pack_descriptors_and_statement() -> None:
    hashes = [t.descriptor_hash(d) for d in PACK["descriptors"]["documents"]]
    assert (
        t.descriptor_set(hashes)
        == PACK["descriptors"]["set_hash"]
        == PACK["context"]["descriptor_set"]
    )
    assert (
        statement_hash(PACK["statement"])
        == PACK["statement_sha256"]
        == PACK["context"]["statement"]
    )


@pytest.mark.parametrize(
    ("name", "label"),
    [("small_pack", "alice"), ("person_at_budget", "alice"), ("group_at_budget", "group A")],
)
def test_pack_signature_is_rebuilt_byte_for_byte(name: str, label: str) -> None:
    v = PACK[name]
    doc = v["doc"]
    assert sign_pack({k: x for k, x in doc.items() if k != "signature"}, ed(label)) == doc
    if "canonical_sha256" in v:
        assert sha256(cjson(doc)).hex() == v["canonical_sha256"]


@pytest.mark.parametrize("name", ["small_pack", "person_at_budget", "group_at_budget"])
def test_pack_passes_the_receiver_checks(name: str) -> None:
    v = PACK[name]
    check_pack(cjson(v["doc"]), pack_context(teasers=v.get("context_teasers")))


@pytest.mark.parametrize("name", ["person_at_budget", "group_at_budget"])
def test_pack_field_sizes(name: str) -> None:
    v = PACK[name]
    sizes = {k: field_size(v["doc"][k]) for k in v["sizes"] if k != "total"}
    assert {**sizes, "total": len(cjson(v["doc"]))} == v["sizes"]
    budgets = PACK["limits"]["budgets"][v["doc"]["kind"]]
    assert all(sizes[k] <= budgets[k] for k in budgets)


@pytest.mark.parametrize("case", PACK["refusals"], ids=lambda c: c["label"])
def test_pack_refusal(case: dict) -> None:
    with pytest.raises(Refused) as e:
        check_pack(case["body"].encode("utf-8"), pack_context())
    assert e.value.code == case["code"]


def test_pack_credential_log_entry_is_rebuilt() -> None:
    doc = PACK["small_pack"]["doc"]
    raw = unb64url(doc["credential"]["token"])
    e = PACK["credential_log_entry"]
    facts = Facts("x", e["node_id"], "", "person", None, (), 0, 0, parse_time(e["expires"]))
    salt = doc["credential"]["log"]["join"]["salt"]
    member = member_commit(doc["subject"], salt)
    assert log_entry(facts, raw, ed("node A"), member) == e
    assert credential_hash(raw) == e["credential_hash"]


def test_known_tags() -> None:
    for k in PACK["known_tags"]:
        assert known_tag(k["identifier"]).hex() == k["tag"]
    assert (
        email_identifier(" \tAlice.Chen@lab-a.example.org\r\n")
        == "email:alice.chen@lab-a.example.org"
    )


def _entries(raw: bytes) -> list[tuple[bytes, list[int]]]:
    count = struct.unpack(">I", raw[96:100])[0]
    out = []
    for i in range(count):
        e = raw[100 + 64 * i : 164 + 64 * i]
        slots = [struct.unpack(">I", e[32 + 4 * j : 36 + 4 * j])[0] for j in range(8)]
        out.append((e[:32], [s for s in slots if s != 0xFFFFFFFF]))
    return out


def test_known_small_is_rebuilt_byte_for_byte() -> None:
    raw = bytes.fromhex(PACK["known_small"]["hex"])
    info = check_known(raw)
    assert info["count"] == PACK["known_small"]["entries"]
    rebuilt = build_known(
        ed("alice"), info["version"], info["created"], info["vocab"], _entries(raw)
    )
    assert rebuilt == raw


def test_known_full_by_its_rule() -> None:
    t0 = parse_time(PACK["times"]["T0"])
    entries = [
        (known_tag(f"email:user{i}@example.org"), [i, i + 1] if i % 2 == 0 else [])
        for i in range(5000)
    ]
    raw = build_known(ed("alice"), 9, t0, "anagram-vocab-2026-11", entries)
    assert (len(raw), sha256(raw).hex()) == (
        PACK["known_full"]["size"],
        PACK["known_full"]["sha256"],
    )


def test_known_weekday() -> None:
    assert known_weekday(PACK["keys"]["alice"]) == PACK["known_weekday"]["weekday"]


# ---- enclave-messages.json ------------------------------------------------------------

INTAKE = seed(MSG["keys"]["intake_seed_label"])
REPLY = seed(MSG["seed_labels"]["keys"]["reply_alice"])


def test_message_keys() -> None:
    k = MSG["keys"]
    assert x25519_public(INTAKE).hex() == k["intake_public"]
    assert x25519_public(REPLY).hex() == k["reply_alice_public"]
    assert ed("enclave output").hex == k["output_public"] and ed("alice").hex == k["alice"]


def test_sizes_and_codes() -> None:
    assert MSG["sizes"] == {
        "answer": 2048,
        "header": 101,
        "known": 393216,
        "receipt": 1024,
        "slot": 4096,
        "upload": 65536,
    }
    assert list(m.ERRORS) == MSG["errors"]


def _check_request(v: dict) -> bytes:
    sealed = b64(v["sealed_b64"])
    h = m.header(v["class"], MSG["keys"]["attestation_digest"], bytes.fromhex(MSG["keys"]["intake_public"]),
                 bytes.fromhex(v["response_key"]))  # fmt: skip
    assert sealed[:101] == h == bytes.fromhex(v["header_hex"])
    assert m.request_info(h) == bytes.fromhex(v["info_hex"])
    assert len(sealed) == v["size"] and m.request_digest(sealed) == v["request_digest"]
    opened = m.open_request(INTAKE, sealed)
    assert opened is not None and opened[1] == v["body"].encode()
    return opened[1]


def test_upload_is_opened_and_rebuilt() -> None:
    v = MSG["upload"]
    body = _check_request(v)
    assert parse_canonical(body) == PACK["small_pack"]["doc"]
    assert x25519_public(seed(v["response_seed_label"])).hex() == v["response_key"]


@pytest.mark.parametrize("choice", ["yes", "no", "not_now"])
def test_answer_is_opened_and_rebuilt(choice: str) -> None:
    v = MSG["answers"][choice]
    body = _check_request(v["sealed"])
    doc = v["doc"]
    assert body == cjson(doc)
    a = m.answer(ed("alice"), doc["proposal"], choice, doc["card"], parse_time(doc["created"]))
    assert a == doc


def test_answer_filler_is_opened_and_rebuilt() -> None:
    v = MSG["answer_filler"]
    assert _check_request(v["sealed"]) == cjson(m.answer_filler()) == cjson(v["doc"])


@pytest.mark.parametrize("i", range(4))
def test_answer_plan(i: int) -> None:
    v = MSG["answer_plans"][i]
    days, expires = m.answer_plan(parse_time(v["made"]), v["answer_day"])
    assert [t * 86_400 for t in days] == [parse_time(c) for c in v["checkpoints"]]
    assert expires == parse_time(v["expires"])
    assert m.plan_ok(v["checkpoints"], v["expires"], days[0] - 1)
    assert not m.plan_ok(v["checkpoints"], v["expires"], days[0])


def test_card_email_must_be_a_verified_tag() -> None:
    card = MSG["answers"]["yes"]["doc"]["card"]
    assert m.card_ok(card)
    assert known_tag(email_identifier(card["email"])).hex() == MSG["card_email_check"]["email_tag"]


@pytest.mark.parametrize("name", ["receipt_accepted", "receipt_rejected"])
def test_receipt_is_opened_and_checked(name: str) -> None:
    v = MSG[name]
    key = seed(v["response_seed_label"])
    s = m.Sealed(b"", v["request_digest"], key, b"")
    doc = m.open_receipt(s, b64(v["sealed_b64"]), {MSG["keys"]["output_public"]})
    assert doc == v["doc"]
    assert ed("enclave output").sign_doc("anagram/v1/enclave/sign/receipt", doc) == doc


@pytest.mark.parametrize("kind", ["empty", "proposal", "reveal", "ended"])
def test_slot_is_opened_and_checked(kind: str) -> None:
    v = MSG["slots"][kind]
    assert m.slot_address(v["day"], x25519_public(REPLY)).hex() == v["address"]
    doc = m.open_slot(REPLY, v["day"], b64(v["sealed_b64"]), {MSG["keys"]["output_public"]})
    assert doc == v["doc"]
    assert ed("enclave output").sign_doc("anagram/v1/enclave/sign/slot", doc) == doc


def test_fillers_are_rebuilt() -> None:
    f = MSG["filler"]
    assert m.slot_filler(bytes.fromhex(f["node_secret"]), bytes.fromhex(f["address"])) == b64(
        f["filler_b64"]
    )
    r = MSG["receipt_filler"]
    assert m.receipt_filler(bytes.fromhex(r["node_secret"]), r["request_digest"]) == b64(
        r["filler_b64"]
    )


def test_slot_batch_is_rebuilt() -> None:
    b = MSG["slot_batch"]
    entries = [
        (bytes.fromhex(MSG["slots"]["empty"]["address"]), b64(MSG["slots"]["empty"]["sealed_b64"])),
        (bytes.fromhex(MSG["filler"]["address"]), b64(MSG["filler"]["filler_b64"])),
    ]
    raw = struct.pack(">II", b["day"], 2) + b"".join(a + s for a, s in sorted(entries))
    assert (len(raw), sha256(raw).hex()) == (b["size"], b["sha256"])


def test_withdrawal_and_cover_are_rebuilt() -> None:
    w = MSG["withdrawal"]["doc"]
    assert (
        m.withdrawal(
            ed("alice"), bytes.fromhex(w["reply_key"]), w["version"], parse_time(w["created"])
        )
        == w
    )
    c = MSG["cover"]["doc"]
    cover = m.cover(
        ed("alice"), bytes.fromhex(c["reply_key"]), c["credential"], parse_time(c["created"])
    )
    assert cover == c and cjson(cover) == MSG["cover"]["body"].encode()


def test_node_request_signature_is_rebuilt() -> None:
    v = MSG["node_request"]
    p = json.loads(v["payload"])
    payload = m.node_request_payload(v["audience"], bytes.fromhex(v["body_hex"]), p["method"], p["node"],
                                     v["nonce"], p["path"], parse_time(p["time"]))  # fmt: skip
    assert payload == v["payload"].encode()
    sig = ed("node A").sign("anagram/v1/net/sign/node-request", payload)
    assert ed("node A").hex == v["node_key"] and sig.hex() == v["signature"]


def test_known_padding() -> None:
    raw = bytes.fromhex(PACK["known_small"]["hex"])
    v = MSG["known_padding"]
    padded = pad(raw, 393_216 - 149)
    assert sha256(raw).hex() == v["body_sha256"] and sha256(padded).hex() == v["padded_sha256"]
    assert len(padded) == v["plaintext_size"] and unpad(padded) == raw


def test_message_tags_are_the_spec_tags() -> None:
    assert len(set(MSG["tags"])) == 13 and all(tg.startswith("anagram/v1/") for tg in MSG["tags"])


# -- intake_script and slot_script, by a model written from the spec text --


def _intake_model(steps: list[dict]) -> list[str]:  # noqa: C901
    s = {"version": 0, "upload_day": None, "known_v": 0, "known_t": None, "tomb": None,
         "live": False, "answered": set()}  # fmt: skip
    out = []
    for st in steps:
        a, now, op = st["args"], st["now"], st["op"]
        if op == "pack":
            created = a["created"]
            if created > now + 300:
                out.append("bad_message")
            elif created < now - 48 * 3600:
                out.append("expired")
            elif s["tomb"] and (
                a["version"] <= s["tomb"][0]
                or created <= s["tomb"][1]
                or a["approved_at"] <= s["tomb"][1]
            ):
                out.append("tombstoned")
            elif a["version"] <= s["version"]:
                out.append("old_version")
            elif s["upload_day"] == now // 86400:
                out.append("rate_limited")
            else:
                s.update(version=a["version"], upload_day=now // 86400, live=True)
                out.append("accepted: kept")
        elif op == "answer":
            p = a["proposal"]
            if p == "00000000000000000000000000000000":
                out.append("unknown_proposal")
            elif p in s["answered"]:
                out.append("already_answered")
            else:
                s["answered"].add(p)
                out.append("accepted: kept")
        elif op == "known":
            if not s["live"]:
                out.append("accepted: discarded")
            elif s["tomb"] and a["created"] <= s["tomb"][1]:
                out.append("tombstoned")
            elif a["version"] <= s["known_v"]:
                out.append("old_version")
            elif s["known_t"] is not None and now - s["known_t"] < 6 * 86400:
                out.append("rate_limited")
            else:
                s.update(known_v=a["version"], known_t=now)
                out.append("accepted: kept")
        elif op == "cover":
            if s["upload_day"] == now // 86400:
                out.append("rate_limited")
            else:
                s["upload_day"] = now // 86400
                out.append("accepted: next slot only")
        elif op == "withdraw":
            s.update(version=a["version"], tomb=(a["version"], now), live=False)
            out.append("accepted: tombstone")
    return out


def test_intake_script_by_the_spec_rules() -> None:
    steps = MSG["intake_script"]
    assert _intake_model(steps) == [x["expect"] for x in steps]


def _cut(day: int) -> int:
    return day * 86400 - 3600


def _slot_model(steps: list[dict]) -> list:  # noqa: C901
    live = {"subjects": {}, "queues": {}, "batches": {}}
    committed = json.loads(json.dumps(live))
    counter, cosigned_counter, requests = -1, -1, {}
    results = []
    for st in steps:
        op, a = st["op"], st["args"]
        r = None
        if op in ("pack", "cover", "withdraw"):
            live["subjects"][a[0]] = [a[1], a[2], a[3]]
        elif op == "request":
            requests[a[0]] = counter  # the epoch before it
        elif op == "receipt":
            r = "receipt" if cosigned_counter > requests[a[0]] else "filler"
        elif op == "reveal":
            for x, y in ((a[0], a[1]), (a[1], a[0])):
                live["queues"].setdefault(x, []).append(f"reveal of {y}")
        elif op == "epoch":
            counter = cosigned_counter + 1
            r = counter
            pending = json.loads(json.dumps(live))
        elif op == "cosign":
            cosigned_counter = counter
            committed = pending
        elif op == "crash":
            live = json.loads(json.dumps(committed))
            counter = cosigned_counter
        elif op == "make_batch":
            day = a[0]
            batch = []
            for name, (node, reply, time) in sorted(live["subjects"].items()):
                q = live["queues"].get(name, [])
                if _cut(day) - 48 * 3600 < time <= _cut(day) or q:
                    batch.append([name, node, reply, q.pop(0) if q else "empty"])
            live["batches"][str(day)] = batch
        elif op == "serve":
            b = committed["batches"].get(str(a[0]))
            r = "not_ready" if b is None else [[n, rp, it] for n, nd, rp, it in b if nd == a[1]]
        results.append(r)
    return results


def test_slot_script_by_the_spec_rules() -> None:
    steps = MSG["slot_script"]
    assert _slot_model(steps) == [x["result"] for x in steps]


# ---- network.json -----------------------------------------------------------------------


def test_node_ids_and_subject_hash() -> None:
    k = NET["keys"]
    assert m.node_id(bytes.fromhex(k["node_a"])) == NET["node_ids"]["node_a"]
    assert m.node_id(bytes.fromhex(k["node_b"])) == NET["node_ids"]["node_b"]
    sh = tagged_hash("anagram/v1/net/subject", bytes.fromhex(PACK["keys"]["alice"])).hex()
    assert sh == NET["subject_hash_alice"]


SIGNERS = {NET["keys"][k]: ed(lbl) for k, lbl in (
    ("roster", "roster"), ("roster_v2", "roster v2"), ("node_a", "node A"), ("node_b", "node B"),
    ("node_b_v2", "node B v2"))}  # fmt: skip


@pytest.mark.parametrize("which", ["roster_events", "node_a_events", "node_b_events"])
def test_control_events_are_rebuilt(which: str) -> None:
    prev = "0" * 64
    for item in NET[which]:
        e = item["event"]
        assert tagged_hash("anagram/v1/net/control-event", cjson(e)).hex() == item["hash"]
        assert SIGNERS[e["signer"]].sign_doc("anagram/v1/net/sign/control-event", e) == e
        if e["seq"] == 0 or which == "roster_events":
            assert e["prev"] == prev
        prev = item["hash"]


def test_roster_checkpoint_is_rebuilt() -> None:
    rc = NET["roster_checkpoint"]
    assert SIGNERS[rc["signer"]].sign_doc("anagram/v1/net/sign/roster-checkpoint", rc) == rc


def _facts(v: dict) -> Facts:
    f = v["facts"]
    return Facts(f["network"], f["node"], f["subject"], f["kind"], f["pid"], tuple(f["email_tags"]),
                 f["control_head"], parse_time(f["issued"]), parse_time(f["expires"]))  # fmt: skip


@pytest.mark.parametrize("name", ["member_credential", "group_credential"])
def test_member_credential_source_and_hash(name: str) -> None:
    import biscuit_auth as bisc

    v = NET[name]
    assert _facts(v).source() == v["datalog"]
    root = bisc.PublicKey.from_bytes(bytes.fromhex(NET["keys"]["node_a"]), bisc.Algorithm.Ed25519)
    tok = bisc.Biscuit.from_base64(v["token"], root)
    assert tok.block_count() == 1 and tok.block_source(0) == v["datalog"]
    if name == "member_credential":
        raw = unb64url(v["token"])
        assert credential_hash(raw) == v["hash"]
        assert log_entry(_facts(v), raw, ed("node A")) == v["log_entry"]
        member = member_commit(v["facts"]["subject"], v["join_salt"])
        assert log_entry(_facts(v), raw, ed("node A"), member) == v["join_log_entry"]


def test_joins_and_new_member_limit() -> None:
    v = NET["issuance"]
    for c in v["cases"]:
        try:
            check_join(
                v["entries"], c["join_index"], c["node"], c["subject"], c["salt"], v["limit"]
            )
            code = "ok"
        except Refused as e:
            code = e.code
        assert code == c["expect"], c["name"]
    counts: dict[str, dict[str, int]] = {}
    for node, month, r in join_ranks(v["entries"]).values():
        counts.setdefault(month, {})[node] = max(r, counts.get(month, {}).get(node, 0))
    assert {k: dict(sorted(n.items())) for k, n in counts.items()} == v["counts"]


def test_node_credential_source() -> None:
    import biscuit_auth as bisc

    v = NET["node_credential"]
    root = bisc.PublicKey.from_bytes(bytes.fromhex(v["root_key"]), bisc.Algorithm.Ed25519)
    assert bisc.Biscuit.from_base64(v["token"], root).block_source(0) == v["datalog"]


def test_fallback_credential_and_request_are_rebuilt() -> None:
    fb = NET["fallback_member_credential"]
    assert ed("node A").sign_doc("anagram/v1/net/sign/member-credential", fb["doc"]) == fb["doc"]
    assert cjson(fb["doc"]) == fb["canonical"].encode()
    cr = NET["credential_request"]
    assert ed("alice").sign_doc("anagram/v1/net/sign/credential-request", cr) == cr
    assert ed("alice device").hex == cr["device"]


@pytest.mark.parametrize("case", NET["biscuit_refusals"], ids=lambda c: c["case"])
def test_biscuit_refusal(case: dict) -> None:
    facts = NET["member_credential"]["facts"]
    cred = {"format": "biscuit-v3", "log": {}, "token": case["token"]}
    with pytest.raises(Refused) as e:
        verify_credential(
            cred,
            node_keys={facts["node"]: NET["keys"]["node_a"]},
            network=NET["network"],
            subject=facts["subject"],
            kind="person",
            now=parse_time(case["now"]),
            log_roots={},
        )
    assert e.value.code == case["expect"]


def test_good_credential_passes_until_the_log_proof() -> None:
    v = NET["member_credential"]
    cred = {"format": "biscuit-v3", "log": {}, "token": v["token"]}
    with pytest.raises(Refused, match="bad_credential: log"):
        verify_credential(cred, node_keys={v["facts"]["node"]: v["root_key"]}, network=NET["network"],
                          subject=v["facts"]["subject"], kind="person", now=parse_time(NET["now"]),
                          log_roots={})  # fmt: skip
    assert b64url(unb64url(v["token"])) == v["token"]


# ---- enclave-trust.json -------------------------------------------------------------------

PINS = t.Pins.from_vector(TRUST["roots"])
BASE = TRUST["base_entries"]


def _log(case: dict) -> t.Log:
    log = t.Log(PINS, BASE + case["extra_entries"])
    for note in case.get("checkpoints", []):
        log.accept(note)
    return log


def test_base_entries_digests_and_leaves() -> None:
    assert [t.entry_digest(e) for e in BASE] == TRUST["base_entry_digests"]
    assert [cjson(e).hex() for e in BASE] == TRUST["base_leaves_hex"]
    assert all(t.entry_ok(e) for e in BASE)
    log = t.Log(PINS, BASE)
    for note in TRUST["base_checkpoints"]:
        log.accept(note)


@pytest.mark.parametrize("name", [c["name"] for c in TRUST["attestation_cases"]])
def test_attestation_case(name: str) -> None:
    case = next(c for c in TRUST["attestation_cases"] if c["name"] == name)
    log = _log(case)
    try:
        t.verify_attestation(log, case["doc"], case["subject"], log.now(case["now"]))
        got = "ok"
    except Refused as r:
        got = r.code
    assert got == case["expect"]


@pytest.mark.parametrize("name", [c["name"] for c in TRUST["release_cases"]])
def test_release_case(name: str) -> None:
    case = next(c for c in TRUST["release_cases"] if c["name"] == name)
    log = _log(case)
    try:
        t.accept_release(log, case["release"], case["app_version"], log.now(case["now"]))
        got = "ok"
    except Refused as r:
        got = r.code
    assert got == case["expect"]


@pytest.mark.parametrize("case", TRUST["line_cases"], ids=lambda c: c["name"])
def test_line_case(case: dict) -> None:
    log = _log(case)
    got = "ok" if t.line_authorised(log, case["line"], None) else "line_not_authorised"
    assert got == case["expect"]


@pytest.mark.parametrize("case", TRUST["writer_cases"], ids=lambda c: c["name"])
def test_writer_case(case: dict) -> None:
    forked, writer, _latest = t.line_state(_log(case), BASE[5]["line_id"])
    assert (forked, None if forked else writer) == (case["forked"], case["writer"])


def test_descriptors() -> None:
    d = TRUST["descriptors"]
    assert [t.descriptor_hash(x) for x in d["documents"]] == d["hashes"]
    assert t.descriptor_set(d["hashes"]) == d["set_hash"]
    assert statement_hash(d["documents"][0]["body"]["consent_statement"]) == d["statement_sha256"]
    t.check_descriptors(d["documents"], d["hashes"])
    for bad in d["bad"]:
        assert not t.descriptor_ok(bad["doc"]), bad["name"]
    for bad in d["bad_sets"]:
        with pytest.raises(Refused):
            t.check_descriptors(bad["documents"], bad["hashes"])
    s = d["shard_example"]
    assert t.shard(s["subject"], s["n"]) == s["shard"]


@pytest.mark.parametrize("profile", sorted(TRUST["measurements"]))
def test_measurement(profile: str) -> None:
    v = TRUST["measurements"][profile]
    assert t.measurement(profile, v["reference"]) == v["measurement"]


def test_binding() -> None:
    b = TRUST["binding"]
    i = b["inputs"]
    doc = {**i, "descriptor_hashes": i["descriptor_hashes"]}
    assert t.descriptor_set(i["descriptor_hashes"]) == i["descriptor_set"]
    value = t.binding(doc, bytes.fromhex(i["checkpoint"]))
    assert value.hex() == b["value"]
    assert t.gpu_nonce(value).hex() == b["gpu_nonce"]
    gpu = bytes.fromhex(b["gpu_evidence_example_hex"])
    assert t.report_data_gpu(value, gpu).hex() == b["report_data_with_gpu"]


def _pack_age_and_tombstone(created: int, version: int, now: int, tomb: dict) -> str:
    """pack.md 8 as written (enclave-trust.md 6.3 uses it as is)."""
    if created > now + 300:
        return "bad_message"
    if created < now - 48 * 3600:
        return "expired"
    alive = now < tomb["time"] + TRUST["tombstone"]["life_seconds"]
    if alive and (version <= tomb["version"] or created <= tomb["time"]):
        return "tombstoned"
    return "ok"


def test_decline_id_includes_the_match_type() -> None:
    v = TRUST["decline"]
    assert v["life_seconds"] == 365 * 86_400
    for c in v["cases"]:
        assert t.decline_id(c["decliner"], c["other"], c["type"]) == c["decline_id"]
    assert len({c["decline_id"] for c in v["cases"]}) == len(v["cases"])


def test_tombstone() -> None:
    v = TRUST["tombstone"]
    assert t.tombstone_id(v["subject"]) == v["tombstone_id"]
    assert v["life_seconds"] == 38 * 86400
    for c in v["cases"]:
        assert (
            _pack_age_and_tombstone(c["created"], c["version"], c["now"], v["tombstone"])
            == c["expect"]
        ), c["name"]


@pytest.mark.parametrize("case", TRUST["clock"], ids=lambda c: c["name"])
def test_clock_rule(case: dict) -> None:
    safe = t.clock_safe(
        case["lower"], case["upper"], case["max_seen"], case["host"], case["fresh_age"]
    )
    assert ("ok" if safe else "clock_unsafe") == case["expect"]


def test_snapshot_is_rebuilt_byte_for_byte() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    v = TRUST["snapshot"]["sealed_counter_1"]
    sealed = bytes.fromhex(v["sealed_hex"])
    hlen = struct.unpack(">I", sealed[:4])[0]
    header = sealed[4 : 4 + hlen]
    assert header == cjson(v["header"])
    nonce = sealed[4 + hlen : 16 + hlen]
    aead = ChaCha20Poly1305(bytes.fromhex(v["state_key_hex"]))
    plain = aead.decrypt(nonce, sealed[16 + hlen :], header)
    assert len(plain) == v["header"]["size"] and unpad(plain) is not None
    rebuilt = struct.pack(">I", hlen) + header + nonce + aead.encrypt(nonce, plain, header)
    assert rebuilt == sealed and sha256(sealed).hex() == v["digest"]


def test_handoff_message_opens() -> None:
    hm = TRUST["handoff_messages"]
    ok = next(c for c in hm["cases"] if c["name"] == "ok")["msg"]
    assert (
        t.attestation_digest(hm["successor_attestation"])
        == hm["successor_digest"]
        == ok["successor"]
    )
    assert verify_doc(ok["signer"], "anagram/v1/enclave/sign/handoff", ok)
    info = b"\x1f" + b"anagram/v1/enclave/hpke/handoff" + bytes.fromhex(ok["successor"])
    plain = hpke_open(
        bytes.fromhex(hm["successor_intake_private_hex"]), b64(ok["ciphertext"]), info
    )
    body = parse_canonical(plain)
    assert body == {"counter": ok["counter"], "line_id": ok["line_id"],
                    "snapshot_digest": ok["snapshot_digest"], "state_key": hm["state_key_hex"]}  # fmt: skip


def test_trust_tags() -> None:
    assert len(TRUST["tags"]) == len(set(TRUST["tags"])) == 26
