"""Vectors for spec/network.md (`spec/vectors/network.json`)."""

from __future__ import annotations

from dataclasses import replace

from anagram.core.canonical import canonical_json
from anagram.core.signed import b64url
from anagram.network.formats import credential as cred
from anagram.network.formats import roster as net
from anagram.network.formats.strict import DAY, Refused, fmt_time, parse_time
from anagram.network.matching.trust.issuance import Issuance, check_join
from anagram.vectors.net.build_pack import NODE_A, NODE_B, member_facts
from anagram.vectors.net.fixtures import NETWORK, T0, Reuse, ed, seed_labels

ROSTER_KEY = ed("roster")
ROSTER_KEY_2 = ed("roster v2")
NODE_A_KEY = ed("node A")
NODE_B_KEY = ed("node B")
NODE_B_KEY_2 = ed("node B v2")
POLICY = {
    "credential_formats": [cred.FORMAT_BISCUIT],
    "credential_max_life": 86_400,
    "new_members_per_month": 200,
    "node_invites_per_quarter": 2,
    "roster_max_age": 3_600,
    "schema": "anagram.net.policy.v1",
}


def record(key: bytes, name: str, domain: str, ror: str | None, kind: str) -> dict:
    return {
        "admin": f"admin@{domain}",
        "affiliation": name,
        "domain": domain,
        "id": net.node_id(key),
        "key": key.hex(),
        "kind": kind,
        "ror": ror,
        "url": f"https://anagram.{domain}",
    }


REC_A = record(
    NODE_A_KEY.public_bytes(),
    "Chen Lab, Example University",
    "lab-a.example.org",
    "012345678",
    "lab",
)
REC_B = record(
    NODE_B_KEY.public_bytes(), "Okafor Group, Sample Institute", "lab-b.example.org", None, "lab"
)


class Builder:
    def __init__(self, chain: str) -> None:
        self.chain = chain
        self.events: list[dict] = []

    def add(self, kind: str, body: dict, time: int, key) -> dict:
        prev = net.event_hash(self.events[-1]) if self.events else net.ZERO
        ev = net.make_event(self.chain, len(self.events), prev, kind, body, time, key)
        self.events.append(ev)
        return ev


def roster_events() -> list[dict]:
    b = Builder(net.ROSTER)
    t = T0 - 30 * DAY
    b.add(
        "roster_created",
        {"network": NETWORK, "roster_key": ROSTER_KEY.public_bytes().hex()},
        t,
        ROSTER_KEY,
    )
    b.add(
        "node_admitted",
        {"endorsement": None, "endorser": net.ROSTER, "node": REC_A},
        t + 60,
        ROSTER_KEY,
    )
    endorsement = NODE_A_KEY.sign(net.TAG_SIGN_ENDORSEMENT, canonical_json(REC_B)).hex()
    b.add(
        "node_admitted",
        {"endorsement": endorsement, "endorser": NODE_A, "node": REC_B},
        t + 120,
        ROSTER_KEY,
    )
    b.add(
        "policy_updated",
        {"effective": fmt_time(t + 14 * DAY), "policy": POLICY},
        t + 180,
        ROSTER_KEY,
    )
    new_key = NODE_B_KEY_2.public_bytes().hex()
    proof = NODE_B_KEY.sign(
        net.TAG_SIGN_KEY_PROOF, canonical_json({"new_key": new_key, "node": NODE_B})
    )
    body = {"chain_seq": 0, "new_key": new_key, "node": NODE_B, "proof": proof.hex()}
    b.add("node_key_rotated", body, t + DAY, ROSTER_KEY)
    mallory = net.subject_hash(ed("mallory").public_bytes())
    b.add("ban", {"reason": "abuse", "subject": mallory}, t + 2 * DAY, ROSTER_KEY)
    b.add(
        "roster_key_rotated",
        {"new_key": ROSTER_KEY_2.public_bytes().hex()},
        t + 3 * DAY,
        ROSTER_KEY,
    )
    b.add(
        "node_updated",
        {
            "endorsement": None,
            "endorser": net.ROSTER,
            "node": {**REC_A, "affiliation": "Chen Lab, Example University (Biology)"},
        },
        t + 4 * DAY,
        ROSTER_KEY_2,
    )
    return b.events


def node_a_events() -> list[dict]:
    b = Builder(NODE_A)
    t = T0 - 10 * DAY
    carol = net.subject_hash(ed("carol").public_bytes())
    b.add("member_left", {"reason": "moved", "subject": carol}, t, NODE_A_KEY)
    revoked = cred.credential_hash(b"anagram net vector: a revoked token").hex()
    b.add(
        "credential_revoked", {"credential": revoked, "reason": "compromised"}, t + 60, NODE_A_KEY
    )
    return b.events


def node_b_events() -> list[dict]:
    b = Builder(NODE_B)
    dave = net.subject_hash(ed("dave").public_bytes())
    b.add("member_removed", {"reason": "removed", "subject": dave}, T0 - 29 * DAY, NODE_B_KEY)
    erin = net.subject_hash(ed("erin").public_bytes())
    b.add("member_left", {"reason": "left", "subject": erin}, T0 - 5 * DAY, NODE_B_KEY_2)
    return b.events


def network_state() -> net.Network:
    state = net.Network(NETWORK, ROSTER_KEY.public_bytes().hex())
    for ev in roster_events() + node_a_events() + node_b_events():
        state.receive(ev)
    return state


def ordering_cases() -> list[dict]:
    """Events given out of order, a gap, and a fork; the state after each step."""
    events = node_a_events()
    cases = []
    state = net.Network(NETWORK, ROSTER_KEY.public_bytes().hex())
    for ev in roster_events():
        state.receive(ev)
    third = net.make_event(
        NODE_A,
        2,
        net.event_hash(events[1]),
        "member_removed",
        {"reason": "removed", "subject": "11" * 32},
        T0 - DAY,
        NODE_A_KEY,
    )
    for label, ev in (
        ("seq 2 first", third),
        ("seq 0", events[0]),
        ("seq 1 fills the gap", events[1]),
    ):
        state.receive(ev)
        ch = state.chain(NODE_A)
        cases.append({"step": label, "seq": ev["seq"], "applied": ch.count, "stopped": ch.stopped})
    fork = net.make_event(
        NODE_A,
        1,
        net.event_hash(events[0]),
        "member_left",
        {"reason": "left", "subject": "22" * 32},
        T0,
        NODE_A_KEY,
    )
    try:
        state.receive(fork)
        result = "accepted"
    except Refused as exc:
        result = exc.code
    cases.append(
        {
            "step": "fork at seq 1",
            "seq": 1,
            "result": result,
            "stopped": state.chain(NODE_A).stopped,
        }
    )
    return cases, [third, fork]


def usable_cases(reuse: Reuse) -> list[dict]:
    state = network_state()
    alice = member_facts("alice")
    raw = reuse.token("alice credential", alice, NODE_A_KEY, alice.issued + 60)
    cases = [("alice", alice, raw)]
    cases.append(("mallory (banned)", member_facts("mallory"), raw))
    cases.append(
        (
            "carol, credential issued before member_left",
            replace(member_facts("carol"), issued=T0 - 11 * DAY, expires=T0 - 10 * DAY + 3_600),
            raw,
        )
    )
    cases.append(("control_head ahead of the node chain", replace(alice, control_head=5), raw))
    out = []
    for label, facts, token in cases:
        try:
            state.credential_usable(facts, token)
            result = "usable"
        except Refused as exc:
            result = exc.code
        out.append(
            {
                "case": label,
                "subject": facts.subject,
                "issued": fmt_time(facts.issued),
                "control_head": facts.control_head,
                "expect": result,
            }
        )
    revoked = b"anagram net vector: a revoked token"
    try:
        state.credential_usable(alice, revoked)
        result = "usable"
    except Refused as exc:
        result = exc.code
    out.append(
        {"case": "revoked credential bytes", "token_utf8": revoked.decode(), "expect": result}
    )
    return out


def biscuit_refusals(reuse: Reuse) -> list[dict]:
    """Tokens that break section 6.1, and what a verifier answers (W4
    finding M-a). Each is signed by the right node key, so only the block
    content is wrong."""
    alice = member_facts("alice")
    src = cred.biscuit_source(alice)
    check = f"check if time($t), $t < {fmt_time(alice.expires)};\n"
    tag = "ab" * 32
    future = member_facts("alice", issued=T0 + 3_600)
    cases = [
        ("extra_fact", src + 'role("admin");\n', None, "bad_credential"),
        ("extra_rule", src + f'email_tag(hex:{tag}) <- kind("person");\n', None, "bad_credential"),
        (
            "extra_check_that_fails",
            src + "check if time($t), $t < 2020-01-01T00:00:00Z;\n",
            None,
            "bad_credential",
        ),
        (
            "check_later_than_expires",
            src.replace(check, "check if time($t), $t < 2030-01-01T00:00:00Z;\n"),
            None,
            "bad_credential",
        ),
        ("no_check", src.replace(check, ""), None, "bad_credential"),
        ("attenuation_block", src, "check if true;", "bad_credential"),
        ("issued_in_the_future", cred.biscuit_source(future), None, "bad_credential"),
        (
            "node_marker",
            src.replace('"member_credential"', '"node_credential"'),
            None,
            "bad_credential",
        ),
    ]
    out = []
    for label, source, extra, expect in cases:
        raw = reuse.source_token(f"misuse {label}", source, NODE_A_KEY, extra)
        out.append({"case": label, "expect": expect, "now": fmt_time(T0), "token": b64url(raw)})
    valid = reuse.token("alice credential", alice, NODE_A_KEY, alice.issued + 60)
    for label, now, key in (
        ("expired", alice.expires, NODE_A_KEY),
        ("other_root_key", T0, NODE_B_KEY),
    ):
        out.append(
            {
                "case": label,
                "expect": _read_code(valid, key.public_bytes().hex(), now),
                "now": fmt_time(now),
                "root_key": key.public_bytes().hex(),
                "token": b64url(valid),
            }
        )
    return out


def _subject(n: int) -> str:
    return ed(f"new member {n}").public_bytes().hex()


def _salt(n: int) -> str:
    return f"{n:032x}"


def issuance_cases() -> dict:
    """New members of each node and month (section 6.7), with
    a limit of 2 so the vector stays small. Entries are in log order; a join
    entry has `member`, a renewal has null; the month is the UTC month of
    `expires`. Each case is a credential that names a join entry."""
    limit = 2
    end = parse_time("2026-11-30T23:30:00Z", "end")
    log = [  # (node, subject number of a join entry or None, expires)
        (NODE_A, 1, T0),
        (None, None, None),  # another kind of entry
        (NODE_B, 5, T0 + 60),
        (NODE_A, None, T0 + DAY),  # renewals of node A
        (NODE_A, 2, T0 + 120),
        (NODE_A, None, T0 + DAY + 60),
        (NODE_A, 3, T0 + 180),  # the third new member of node A in 2026-11
        (NODE_A, 4, end + 3_600),  # expires in 2026-12: a new month
    ]
    entries = []
    for node, n, t in log:
        if node is None:
            entries.append({"kind": "roster_checkpoint"})
            continue
        member = cred.member_commit(_subject(n), _salt(n)) if n else None
        entries.append(
            {"expires": fmt_time(t), "kind": "member_credential", "member": member, "node_id": node}
        )
    counts = Issuance()
    counts.update(entries, 0)
    uses = [  # (case, node, join index, subject number, salt number)
        ("join of member 1", NODE_A, 0, 1, 1),
        ("renewal of member 1", NODE_A, 0, 1, 1),
        ("join of member 2", NODE_A, 4, 2, 2),
        ("join of member 3: over the limit", NODE_A, 6, 3, 3),
        ("join of member 4: a new month", NODE_A, 7, 4, 4),
        ("member 5 of node B", NODE_B, 2, 5, 5),
        ("a renewal entry is not a join entry", NODE_A, 3, 1, 1),
        ("another subject's join entry", NODE_A, 0, 2, 2),
        ("another node's join entry", NODE_A, 2, 5, 5),
    ]
    cases = []
    for name, node, at, n, s in uses:
        try:
            check_join(counts, at, node, _subject(n), _salt(s), limit)
            code = "ok"
        except Refused as exc:
            code = exc.code
        case = {"node": node, "join_index": at, "subject": _subject(n), "salt": _salt(s)}
        cases.append({"name": name, **case, "expect": code})
    return {
        "limit": limit,
        "entries": entries,
        "cases": cases,
        "counts": {m: counts.of_month(m) for m in sorted(counts.counts)},
    }


def _read_code(raw: bytes, root_hex: str, now: int) -> str:
    try:
        cred.read_member_biscuit(raw, root_hex, now)
    except Refused as exc:
        return exc.code
    return "usable"


def build(reuse: Reuse) -> dict:
    alice = member_facts("alice")
    raw = reuse.token("alice credential", alice, NODE_A_KEY, alice.issued + 60)
    group = member_facts("group A", kind="group")
    graw = reuse.token("group credential", group, NODE_A_KEY, group.issued + 60)
    node = cred.NodeFacts(
        NETWORK,
        NODE_A,
        NODE_A_KEY.public_bytes().hex(),
        "lab",
        "lab-a.example.org",
        "012345678",
        T0 - 3_600,
        T0 - 3_600 + 86_400,
    )
    nraw = reuse.token("node credential A", node, ROSTER_KEY, node.issued + 60)
    fallback = cred.member_json(alice, NODE_A_KEY)
    roster = roster_events()
    state = network_state()
    checkpoint = net.roster_checkpoint(
        NETWORK, len(roster) - 1, net.event_hash(roster[-1]), T0 - 600, ROSTER_KEY_2
    )
    ordering, extra = ordering_cases()
    return {
        "description": "Network roster, control events, credentials (spec/network.md). Biscuit "
        "tokens are random: a verifier checks them; it recomputes every other value.",
        "tags": [
            net.TAG_NODE_ID,
            net.TAG_SUBJECT,
            net.TAG_EVENT,
            net.TAG_SIGN_EVENT,
            net.TAG_SIGN_CHECKPOINT,
            net.TAG_SIGN_KEY_PROOF,
            net.TAG_SIGN_ENDORSEMENT,
            net.TAG_SIGN_CREDENTIAL_REQUEST,
            cred.TAG_CREDENTIAL,
            cred.TAG_SIGN_MEMBER_JSON,
        ],
        "network": NETWORK,
        "now": fmt_time(T0),
        "seed_labels": seed_labels(
            alice="alice",
            alice_device="alice device",
            carol="carol",
            dave="dave",
            erin="erin",
            mallory="mallory",
            node_a="node A",
            node_b="node B",
            node_b_v2="node B v2",
            roster="roster",
            roster_v2="roster v2",
        ),
        "keys": {
            "roster": ROSTER_KEY.public_bytes().hex(),
            "roster_v2": ROSTER_KEY_2.public_bytes().hex(),
            "node_a": NODE_A_KEY.public_bytes().hex(),
            "node_b": NODE_B_KEY.public_bytes().hex(),
            "node_b_v2": NODE_B_KEY_2.public_bytes().hex(),
        },
        "node_ids": {"node_a": NODE_A, "node_b": NODE_B},
        "roster_events": [{"event": ev, "hash": net.event_hash(ev).hex()} for ev in roster],
        "node_a_events": [
            {"event": ev, "hash": net.event_hash(ev).hex()} for ev in node_a_events()
        ],
        "node_b_events": [
            {"event": ev, "hash": net.event_hash(ev).hex()} for ev in node_b_events()
        ],
        "roster_checkpoint": checkpoint,
        "state": {
            "nodes": sorted(state.nodes),
            "node_b_key": state.nodes[NODE_B]["key"],
            "roster_key": state.roster_key,
            "bans": sorted(state.bans),
            "policy": state.policy,
            "revoked_credentials": sorted(state.revoked_credentials),
            "gone_subjects": {
                k: [v[0], fmt_time(v[1])] for k, v in sorted(state.gone_subjects.items())
            },
        },
        "ordering": {"extra_events": extra, "steps": ordering},
        "member_credential": {
            "datalog": cred.biscuit_source(alice),
            "token": b64url(raw),
            "root_key": NODE_A_KEY.public_bytes().hex(),
            "hash": cred.credential_hash(raw).hex(),
            "log_entry": cred.log_entry(alice, raw, NODE_A_KEY),
            "join_log_entry": cred.log_entry(
                alice, raw, NODE_A_KEY, cred.member_commit(alice.subject, _salt(0))
            ),
            "join_salt": _salt(0),
            "facts": _facts(alice),
        },
        "group_credential": {
            "datalog": cred.biscuit_source(group),
            "token": b64url(graw),
            "facts": _facts(group),
        },
        "node_credential": {
            "datalog": cred.biscuit_source(node),
            "token": b64url(nraw),
            "root_key": ROSTER_KEY.public_bytes().hex(),
        },
        "fallback_member_credential": {
            "doc": fallback,
            "canonical": canonical_json(fallback).decode(),
        },
        "credential_request": net.credential_request(
            ed("alice"), ed("alice device").public_bytes().hex(), NODE_A, "5a" * 16, T0
        ),
        "subject_hash_alice": net.subject_hash(ed("alice").public_bytes()),
        "usable": usable_cases(reuse),
        "issuance": issuance_cases(),
        "biscuit_refusals": biscuit_refusals(reuse),
    }


def _facts(f: cred.MemberFacts) -> dict:
    return {
        "control_head": f.control_head,
        "email_tags": list(f.email_tags),
        "expires": fmt_time(f.expires),
        "issued": fmt_time(f.issued),
        "kind": f.kind,
        "network": f.network,
        "node": f.node,
        "pid": f.pid,
        "subject": f.subject,
    }
