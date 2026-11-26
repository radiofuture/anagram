"""The matching enclave vectors (spec/pack.md, spec/enclave-messages.md,
spec/network.md): the files are current, every deterministic value
recomputes, and every random value (HPKE ciphertext, Biscuit token) verifies."""

from __future__ import annotations

import copy
import hashlib
import json
import random
from pathlib import Path

import pytest

from anagram.core.canonical import canonical_json
from anagram.core.crypto import hpke
from anagram.core.crypto.signing import verify
from anagram.network.formats import credential as cred
from anagram.network.formats import enclave as m
from anagram.network.formats import pack as packs
from anagram.network.formats import roster as net
from anagram.network.formats.strict import Refused, parse_time
from anagram.network.matching.trust.issuance import Issuance, check_join, month_of, policy_limit
from anagram.vectors.net import build as net_build
from anagram.vectors.net.build_network import network_state
from anagram.vectors.net.build_pack import context, full_known
from anagram.vectors.net.fixtures import T0, ed, seed, unb64, x25519

VEC = Path(__file__).parent.parent / "spec" / "vectors"


def load(name: str) -> dict:
    return json.loads((VEC / name).read_text())


PACK = load("pack.json")
MSG = load("enclave-messages.json")
NET = load("network.json")


@pytest.mark.parametrize("name", net_build.FILES)
def test_vectors_are_current(name):
    assert load(name) == json.loads(net_build.dump(net_build.build_all(VEC)[name]))


def _ctx(teasers: bool = False) -> packs.Context:
    roots = {int(k): bytes.fromhex(v) for k, v in PACK["context"]["log_roots"].items()}
    return context(roots, teasers)


# pack.md


def test_small_pack_is_accepted():
    doc, facts = packs.check_pack_bytes(canonical_json(PACK["small_pack"]["doc"]), _ctx())
    assert facts.subject == doc["subject"] == PACK["keys"]["alice"]
    assert hashlib.sha256(canonical_json(doc)).hexdigest() == PACK["small_pack"]["canonical_sha256"]


@pytest.mark.parametrize("name", ["person_at_budget", "group_at_budget"])
def test_pack_at_budget_fits(name):
    doc = PACK[name]["doc"]
    packs.check_pack_bytes(canonical_json(doc), _ctx(teasers=True))
    limits = packs.LIMITS[doc["kind"]]
    sizes = {n: packs.size_of(doc[n]) for n in limits.budgets}
    assert all(sizes[n] <= limits.budgets[n] for n in sizes)
    assert {**sizes, "total": len(canonical_json(doc))} == PACK[name]["sizes"]
    assert len(canonical_json(doc)) <= packs.PACK_MAX
    assert len(doc["lines"]["offers"]) == len(doc["lines"]["wants"]) == limits.lines
    assert len(doc["readings"]) == limits.readings and len(doc["facts"]) == 150


def test_budget_sums_stay_under_the_cap():
    for kind, limits in packs.LIMITS.items():
        assert sum(limits.budgets.values()) + 1_024 <= packs.PACK_MAX, kind
    assert PACK["limits"]["budgets"] == {k: v.budgets for k, v in packs.LIMITS.items()}


@pytest.mark.parametrize("case", PACK["refusals"], ids=lambda c: c["label"])
def test_pack_refusals(case):
    with pytest.raises(Refused) as exc:
        packs.check_pack_bytes(case["body"].encode("utf-8"), _ctx())
    assert exc.value.code == case["code"]


def test_fuzzed_packs_raise_only_refusals():
    """No mutation of a pack crashes the checker; each gives a code of the list."""
    rnd = random.Random(7)  # noqa: S311 - a fixed test sequence
    base = PACK["small_pack"]["doc"]
    values = [None, True, -1, 2**53, "", "x" * 300, [], {}, [1, 1], "\u0000", 1.5]
    for _ in range(300):
        doc = copy.deepcopy(base)
        path = _random_path(rnd, doc)
        _set(doc, path, rnd.choice(values))
        try:
            body = canonical_json(doc)
        except ValueError:
            continue
        try:
            packs.check_pack_bytes(body, _ctx())
        except Refused as exc:
            assert exc.code in m.ERRORS


def _random_path(rnd, doc):
    path = []
    node = doc
    while isinstance(node, dict | list) and node and rnd.random() < 0.7:
        key = rnd.choice(list(node)) if isinstance(node, dict) else rnd.randrange(len(node))
        path.append(key)
        node = node[key]
    return path or ["version"]


def _set(doc, path, value):
    node = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def test_known_objects():
    small = packs.decode_known(bytes.fromhex(PACK["known_small"]["hex"]))
    assert small.subject == PACK["keys"]["alice"] and len(small.entries) == 3
    full = full_known()
    assert len(full) == PACK["known_full"]["size"]
    assert hashlib.sha256(full).hexdigest() == PACK["known_full"]["sha256"]
    assert len(packs.decode_known(full).entries) == packs.KNOWN_MAX_ENTRIES
    assert len(full) + 4 <= m.plaintext_size(m.CLASS_KNOWN)
    tampered = bytearray(full)
    tampered[200] ^= 1
    with pytest.raises(Refused) as exc:
        packs.decode_known(bytes(tampered))
    assert exc.value.code == "bad_signature"


def test_known_tags():
    for row in PACK["known_tags"]:
        assert packs.known_tag(row["identifier"]).hex() == row["tag"]
    assert packs.email_id(" Carol@Example.ORG ") == "email:carol@example.org"


# enclave-messages.md


def _intake():
    priv = x25519("enclave intake")
    pub = hpke.public_bytes(priv)
    return {pub: priv}, {pub: bytes.fromhex(MSG["keys"]["attestation_digest"])}


def _open(sealed: dict) -> bytes:
    raw = unb64(sealed["sealed_b64"])
    assert len(raw) == sealed["size"] == m.SIZES[sealed["class"]]
    assert raw[: m.HEADER].hex() == sealed["header_hex"]
    assert m.request_info(raw[: m.HEADER]).hex() == sealed["info_hex"]
    assert m.request_digest(raw).hex() == sealed["request_digest"]
    req, body = m.open_request(raw, *_intake())
    assert req.response.hex() == sealed["response_key"]
    return body


def test_sealed_upload_opens_to_the_pack():
    body = _open(MSG["upload"])
    assert body == canonical_json(PACK["small_pack"]["doc"]) == MSG["upload"]["body"].encode()
    assert m.upload_kind(body) == "pack"


def test_envelope_refusals():
    raw = bytearray(unb64(MSG["upload"]["sealed_b64"]))
    keys, att = _intake()
    for change, code in (
        (lambda r: r.__setitem__(slice(0, 4), b"XXXX"), "bad_envelope"),
        (lambda r: r.__setitem__(70, r[70] ^ 1), "bad_envelope"),  # response key: info differs
        (lambda r: r.__setitem__(6, r[6] ^ 1), "stale_attestation"),
        (lambda r: r.__setitem__(40, r[40] ^ 1), "unknown_instance_key"),
        (lambda r: r.__setitem__(-1, r[-1] ^ 1), "bad_envelope"),
    ):
        bad = bytearray(raw)
        change(bad)
        with pytest.raises(Refused) as exc:
            m.open_request(bytes(bad), keys, att)
        assert exc.value.code == code
    with pytest.raises(Refused):
        m.open_request(bytes(raw[:-1]), keys, att)


@pytest.mark.parametrize("name", ["receipt_accepted", "receipt_rejected"])
def test_receipts(name):
    v = MSG[name]
    resp = "response 1" if name == "receipt_accepted" else "response 2"
    raw = unb64(v["sealed_b64"])
    assert len(raw) == m.RECEIPT_SIZE
    doc = m.open_receipt(
        x25519(resp), bytes.fromhex(v["request_digest"]), raw, {MSG["keys"]["output_public"]}
    )
    assert doc == v["doc"]
    with pytest.raises(Refused):
        m.open_receipt(x25519(resp), bytes(32), raw, {MSG["keys"]["output_public"]})


def test_receipt_for_the_upload_names_it():
    assert MSG["receipt_accepted"]["request_digest"] == MSG["upload"]["request_digest"]


@pytest.mark.parametrize("choice", ["yes", "no", "not_now"])
def test_answers(choice):
    v = MSG["answers"][choice]
    body = _open(v["sealed"])
    assert body == canonical_json(v["doc"])
    tags = (MSG["card_email_check"]["email_tag"],)
    m.check_answer(v["doc"], tags)
    if choice == "yes":
        with pytest.raises(Refused):
            m.check_answer(v["doc"], ("00" * 32,))


def test_answer_refusals():
    yes = MSG["answers"]["yes"]["doc"]
    no = {**MSG["answers"]["no"]["doc"], "card": yes["card"]}
    for bad in (no, {**yes, "choice": "maybe"}, {**yes, "signature": "00" * 64}):
        with pytest.raises(Refused):
            m.check_answer(bad)


def test_withdrawal_and_cover():
    m.check_withdrawal(MSG["withdrawal"]["doc"])
    assert m.upload_kind(MSG["cover"]["body"].encode()) == "cover"
    assert m.upload_kind(canonical_json(MSG["withdrawal"]["doc"])) == "withdrawal"
    cover = MSG["cover"]["doc"]
    assert canonical_json(cover).decode() == MSG["cover"]["body"]
    facts = m.check_cover(cover, _ctx())
    assert facts.subject == cover["subject"] == PACK["keys"]["alice"]
    assert cover["reply_key"] == PACK["small_pack"]["doc"]["reply_key"]
    for bad in ({**cover, "signature": "00" * 64}, {**cover, "extra": 1}):
        with pytest.raises(Refused):
            m.check_cover(bad, _ctx())


def test_receipt_filler():
    f = MSG["receipt_filler"]
    raw = m.receipt_filler(bytes.fromhex(f["node_secret"]), bytes.fromhex(f["request_digest"]))
    assert raw == unb64(f["filler_b64"]) and len(raw) == m.RECEIPT_SIZE
    assert f["request_digest"] == MSG["upload"]["request_digest"]
    with pytest.raises(Refused):
        m.open_receipt(
            x25519("response 1"),
            bytes.fromhex(f["request_digest"]),
            raw,
            {MSG["keys"]["output_public"]},
        )


def test_slot_script():
    from anagram.vectors.net import slots
    from anagram.vectors.net.build_messages import slot_script

    assert slots.run(slot_script()) == MSG["slot_script"]


def test_slot_rule_after_withdrawal_late_upload_and_crash():
    """W4 re-check R1 and R5: the one 48 hour slot rule, and a resent yes."""
    serves = [r for r in MSG["slot_script"] if r["op"] == "serve"]
    names = {
        (r["args"][0], n[0]) for r in serves if isinstance(r["result"], list) for n in r["result"]
    }
    items = {
        (r["args"][0], n[0]): n[2]
        for r in serves
        if isinstance(r["result"], list)
        for n in r["result"]
    }
    d = serves[0]["args"][0]
    assert (d + 1, "henry") in names and (d + 2, "henry") in names  # after a withdrawal
    assert (d + 1, "ivy") not in names and (d + 2, "ivy") in names  # upload after 23:00
    assert (d + 2, "alice") not in names  # no upload in 48 hours, empty queue
    assert items[(d + 2, "frank")] == "reveal of gina"
    assert items[(d + 2, "gina")] == "reveal of frank"


def test_withdrawal_carries_reply_key():
    doc = MSG["withdrawal"]["doc"]
    assert doc["reply_key"] == MSG["keys"]["reply_alice_public"]
    with pytest.raises(Refused):
        m.check_withdrawal({k: v for k, v in doc.items() if k != "reply_key"})


@pytest.mark.parametrize("case", NET["biscuit_refusals"], ids=lambda c: c["case"])
def test_biscuit_refusals(case):
    root = case.get("root_key", NET["keys"]["node_a"])
    with pytest.raises(Refused) as exc:
        cred.read_member_biscuit(cred.unb64url(case["token"]), root, parse_time(case["now"], "now"))
    assert exc.value.code == case["expect"]


@pytest.mark.parametrize("kind", ["empty", "proposal", "reveal", "ended"])
def test_slots(kind):
    v = MSG["slots"][kind]
    raw = unb64(v["sealed_b64"])
    assert len(raw) == m.SLOT_SIZE
    reply = hpke.public_bytes(x25519("reply alice"))
    assert (
        reply.hex() == MSG["keys"]["reply_alice_public"] == PACK["small_pack"]["doc"]["reply_key"]
    )
    assert m.slot_address(v["day"], reply).hex() == v["address"]
    doc = m.open_slot(x25519("reply alice"), v["day"], raw, {MSG["keys"]["output_public"]})
    assert doc == v["doc"] and doc["item"]["kind"] == kind
    assert m.open_slot(x25519("reply alice"), v["day"] + 1, raw, set()) is None


def test_filler_and_batch():
    f = MSG["filler"]
    filler = m.filler(bytes.fromhex(f["node_secret"]), bytes.fromhex(f["address"]))
    assert filler == unb64(f["filler_b64"]) and len(filler) == m.SLOT_SIZE
    assert m.open_slot(x25519("reply alice"), MSG["slot_batch"]["day"], filler, set()) is None
    b = MSG["slot_batch"]
    slots = {
        bytes.fromhex(MSG["slots"]["empty"]["address"]): unb64(MSG["slots"]["empty"]["sealed_b64"]),
        bytes.fromhex(f["address"]): filler,
    }
    raw = m.slot_batch(b["day"], slots)
    assert len(raw) == b["size"] and hashlib.sha256(raw).hexdigest() == b["sha256"]
    day, back = m.read_batch(raw)
    assert day == b["day"] and [a.hex() for a in back] == b["addresses"]


def test_node_request_signature():
    v = MSG["node_request"]
    body = bytes.fromhex(v["body_hex"])
    nonce = bytes.fromhex(v["nonce"])
    payload = m.node_request_payload(
        "node-" + "ab" * 16, v["audience"], "POST", "/v1/relay/uploads", T0, body, nonce
    )
    assert payload.decode() == v["payload"]
    assert verify(
        bytes.fromhex(v["node_key"]),
        m.TAG_SIGN_NODE_REQUEST,
        payload,
        bytes.fromhex(v["signature"]),
    )


def test_known_padding():
    v = MSG["known_padding"]
    body = bytes.fromhex(PACK["known_small"]["hex"])
    assert hashlib.sha256(body).hexdigest() == v["body_sha256"]
    padded = m.pad(body, v["plaintext_size"])
    assert hashlib.sha256(padded).hexdigest() == v["padded_sha256"]
    assert m.unpad(padded) == body
    with pytest.raises(Refused):
        m.unpad(padded[:-1] + b"\x01")


def test_intake_script():
    from anagram.vectors.net.build_messages import intake_script

    assert intake_script() == MSG["intake_script"]


def test_error_list_is_complete():
    assert MSG["errors"] == list(m.ERRORS) and len(set(m.ERRORS)) == len(m.ERRORS)


# network.md


def test_control_chains_apply_and_hash():
    for key in ("roster_events", "node_a_events", "node_b_events"):
        for row in NET[key]:
            assert net.event_hash(row["event"]).hex() == row["hash"]
    state = network_state()
    assert sorted(state.nodes) == NET["state"]["nodes"]
    assert state.roster_key == NET["state"]["roster_key"] == NET["keys"]["roster_v2"]
    assert state.nodes[NET["node_ids"]["node_b"]]["key"] == NET["keys"]["node_b_v2"]
    assert sorted(state.bans) == NET["state"]["bans"]
    assert state.policy == NET["state"]["policy"]
    net.check_checkpoint(NET["roster_checkpoint"], state, T0)
    with pytest.raises(Refused) as exc:
        net.check_checkpoint(NET["roster_checkpoint"], state, T0 + 2 * 3_600)
    assert exc.value.code == "stale_roster"


def test_event_refusals():
    state = net.Network(NET["network"], NET["keys"]["roster"])
    first = copy.deepcopy(NET["roster_events"][0]["event"])
    first["body"]["network"] = "other.example"
    with pytest.raises(Refused):
        state.receive(first)
    state = net.Network(NET["network"], NET["keys"]["roster"])
    second = NET["roster_events"][1]["event"]
    state.receive(second)  # seq 1 first: held, not applied
    assert state.chain(net.ROSTER).count == 0 and state.chain(net.ROSTER).stopped == "gap"


def test_ordering_cases():
    from anagram.vectors.net.build_network import ordering_cases

    steps, extra = ordering_cases()
    assert steps == NET["ordering"]["steps"] and extra == NET["ordering"]["extra_events"]


def test_usable_cases():
    from anagram.vectors.net.build_network import usable_cases
    from anagram.vectors.net.fixtures import Reuse

    assert usable_cases(Reuse(NET["random"])) == NET["usable"]


def test_issuance_cases():
    v = NET["issuance"]
    counts = Issuance()
    counts.update(v["entries"], 0)
    for c in v["cases"]:
        try:
            check_join(counts, c["join_index"], c["node"], c["subject"], c["salt"], v["limit"])
            code = "ok"
        except Refused as exc:
            code = exc.code
        assert code == c["expect"], c["name"]
    assert {mo: counts.of_month(mo) for mo in sorted(counts.counts)} == v["counts"]


def test_the_201st_new_member_of_a_month_is_over_the_default_limit():
    """network.md 6.7 and 9: the default allows 200 new members per node
    and month. Daily renewals between the joins do not count."""
    limit = policy_limit(None)
    assert limit == 200
    expires = cred.fmt_time(T0 + 3_600)
    entries, joins = [], []
    for n in range(201):
        subject, salt = ed(f"member {n}").public_bytes().hex(), f"{n:032x}"
        joins.append((len(entries), subject, salt))
        member = cred.member_commit(subject, salt)
        for m_ in (member, None, None):  # a join entry, then two renewals
            entries.append(
                {"expires": expires, "kind": "member_credential", "member": m_, "node_id": "a.n"}
            )
    counts = Issuance()
    counts.update(entries, 0)
    for at, subject, salt in joins[:200]:
        check_join(counts, at, "a.n", subject, salt, limit)
    at, subject, salt = joins[200]
    with pytest.raises(Refused) as exc:
        check_join(counts, at, "a.n", subject, salt, limit)
    assert exc.value.code == "issuance_limit"
    assert counts.of_month(month_of(T0 + 3_600)) == {"a.n": 201}


def test_credentials_verify():
    now = parse_time(NET["now"], "now")
    mc = NET["member_credential"]
    raw = cred.unb64url(mc["token"])
    facts = cred.read_member_biscuit(raw, mc["root_key"], now)
    assert cred.biscuit_source(facts) == mc["datalog"]
    assert cred.credential_hash(raw).hex() == mc["hash"]
    node_key = ed("node A")
    assert cred.log_entry(facts, raw, node_key) == mc["log_entry"]
    member = cred.member_commit(facts.subject, mc["join_salt"])
    assert cred.log_entry(facts, raw, node_key, member) == mc["join_log_entry"]
    with pytest.raises(Refused) as exc:
        cred.read_member_biscuit(raw, mc["root_key"], parse_time(mc["facts"]["expires"], "e"))
    assert exc.value.code == "expired"
    with pytest.raises(Refused):
        cred.read_member_biscuit(raw, NET["keys"]["node_b"], now)
    g = NET["group_credential"]
    gfacts = cred.read_member_biscuit(cred.unb64url(g["token"]), mc["root_key"], now)
    assert (
        gfacts.kind == "group"
        and gfacts.pid is None
        and cred.biscuit_source(gfacts) == g["datalog"]
    )
    n = NET["node_credential"]
    nfacts = cred.read_node_biscuit(cred.unb64url(n["token"]), n["root_key"], now)
    assert cred.biscuit_source(nfacts) == n["datalog"]
    fb = NET["fallback_member_credential"]
    assert canonical_json(fb["doc"]).decode() == fb["canonical"]
    assert cred.read_member_json(fb["canonical"].encode(), mc["root_key"], now) == facts


def test_credential_request_and_subject_hash():
    req = NET["credential_request"]
    body = canonical_json({k: v for k, v in req.items() if k != "signature"})
    assert verify(
        bytes.fromhex(req["person_key"]),
        net.TAG_SIGN_CREDENTIAL_REQUEST,
        body,
        bytes.fromhex(req["signature"]),
    )
    alice = bytes.fromhex(PACK["keys"]["alice"])
    assert net.subject_hash(alice) == NET["subject_hash_alice"]
    assert net.node_id(bytes.fromhex(NET["keys"]["node_a"])) == NET["node_ids"]["node_a"]


def test_seeds_are_the_documented_rule():
    assert seed("x") == hashlib.sha256(b"anagram net vector seed: x").digest()


# JSON Schemas (spec/schemas/): every JSON document of the vectors validates.

SCHEMAS = Path(__file__).parent.parent / "spec" / "schemas"


def _validator(file: str, name: str | None):
    import jsonschema

    schema = json.loads((SCHEMAS / file).read_text())
    if name is not None:
        schema = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{name}"}
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _schema_cases():
    yield "pack.schema.json", None, PACK["small_pack"]["doc"]
    yield "pack.schema.json", None, PACK["person_at_budget"]["doc"]
    yield "pack.schema.json", None, PACK["group_at_budget"]["doc"]
    msg = "enclave-messages.schema.json"
    for choice in ("yes", "no", "not_now"):
        yield msg, "answer", MSG["answers"][choice]["doc"]
    yield msg, "answer_filler", MSG["answer_filler"]["doc"]
    yield msg, "withdrawal", MSG["withdrawal"]["doc"]
    yield msg, "cover", MSG["cover"]["doc"]
    yield msg, "receipt", MSG["receipt_accepted"]["doc"]
    yield msg, "receipt", MSG["receipt_rejected"]["doc"]
    for kind in ("empty", "proposal", "reveal", "ended"):
        yield msg, "slot", MSG["slots"][kind]["doc"]
    yield msg, "nodeRequest", json.loads(MSG["node_request"]["payload"])
    nets = "network.schema.json"
    for key in ("roster_events", "node_a_events", "node_b_events"):
        for row in NET[key]:
            yield nets, "controlEvent", row["event"]
    yield nets, "rosterCheckpoint", NET["roster_checkpoint"]
    yield nets, "memberCredentialJson", NET["fallback_member_credential"]["doc"]
    yield nets, "credentialLogEntry", NET["member_credential"]["log_entry"]
    yield nets, "credentialRequest", NET["credential_request"]
    yield nets, "policy", NET["state"]["policy"]


def test_vector_documents_match_the_schemas():
    for file, name, doc in _schema_cases():
        errors = list(_validator(file, name).iter_errors(doc))
        assert not errors, (file, name, errors[:1])


def test_schemas_refuse_extra_fields():
    v = _validator("pack.schema.json", None)
    assert list(v.iter_errors({**PACK["small_pack"]["doc"], "extra": 1}))
    a = _validator("enclave-messages.schema.json", "answer")
    no = MSG["answers"]["no"]["doc"]
    assert list(a.iter_errors({**no, "card": MSG["answers"]["yes"]["doc"]["card"]}))
