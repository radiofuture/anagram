"""Vectors for spec/pack.md (`spec/vectors/pack.json`)."""

from __future__ import annotations

import copy
import hashlib
from typing import Any

from anagram.core.canonical import canonical_json
from anagram.core.crypto import merkle
from anagram.core.signed import b64url
from anagram.network.formats import credential as cred
from anagram.network.formats import pack as packs
from anagram.network.formats.roster import node_id
from anagram.network.formats.strict import DAY, fmt_time
from anagram.vectors.net.fixtures import (
    DESCRIPTOR_SET,
    DESCRIPTORS,
    NETWORK,
    STATEMENT,
    STATEMENT_HASH,
    T0,
    VOCAB,
    Reuse,
    ed,
    seed_labels,
    xpub,
)

NODE_A = node_id(ed("node A").public_bytes())
NODE_B = node_id(ed("node B").public_bytes())
ALICE_EMAIL = "Alice.Chen@Lab-A.example.org"
BIG = 4_000_000_000  # concept indexes with 10 digits, the longest form


def member_facts(
    who: str, kind: str = "person", issued: int = T0 - 3_600, tags: int = 1
) -> cred.MemberFacts:
    email_tags = [packs.known_tag(packs.email_id(ALICE_EMAIL)).hex()]
    email_tags += [hashlib.sha256(f"tag {i}".encode()).hexdigest() for i in range(1, tags)]
    return cred.MemberFacts(
        network=NETWORK,
        node=NODE_A,
        subject=ed(who).public_bytes().hex(),
        kind=kind,
        issued=issued,
        expires=issued + 86_400,
        control_head=2,
        pid=("pid:" + hashlib.sha256(who.encode()).hexdigest()[:32]) if kind == "person" else None,
        email_tags=tuple(sorted(email_tags[:tags])) if kind == "person" else (),
    )


def log_tree(entry: dict, filler: int = 4) -> tuple[dict, bytes]:
    """A small log: `filler` other entries, then `entry`. Return (proof, root)."""
    leaves = [
        merkle.leaf_hash(canonical_json({"filler": i, "kind": "other"})) for i in range(filler)
    ]
    leaves.append(merkle.leaf_hash(canonical_json(entry)))
    sub = merkle.list_subtree(leaves)
    path = merkle.inclusion_path(sub, filler, len(leaves))
    proof = {"hashes": [h.hex() for h in path], "index": filler, "tree_size": len(leaves)}
    return proof, merkle.root(leaves)


def long_proof(entry: dict, size: int) -> tuple[dict, bytes]:
    """A proof with 32 hashes (a tree of more than 2^31 entries): the longest that a pack takes."""
    path = [hashlib.sha256(f"sibling {i}".encode()).digest() for i in range(32)]
    leaf = merkle.leaf_hash(canonical_json(entry))
    root = merkle.root_from_inclusion(leaf, 0, size, path)
    assert root is not None  # noqa: S101 - the shape is fixed
    return {"hashes": [h.hex() for h in path], "index": 0, "tree_size": size}, root


def text_of(n: int, label: str) -> str:
    words = f"{label} cryo-EM transporter maps need molecular dynamics and samples "
    out = (words * (n // len(words) + 1))[:n]
    return out[:-1] + "x" if out.endswith(" ") else out


def _lines(prefix: str, count: int, width: int, types: list[str]) -> list[dict]:
    classes = list(packs.CLASSES)
    return [
        {
            "class": classes[i % len(classes)],
            "concepts": [BIG + 8 * i + j for j in range(8)],
            "id": f"{prefix}{i + 1:02d}",
            "scope": packs.SCOPES[i % 3],
            "text": text_of(width, f"{prefix}{i + 1}"),
            "types": types,
        }
        for i in range(count)
    ]


def _readings(count: int, width: int) -> list[dict]:
    kinds = list(packs.READING_KINDS)
    return [
        {
            "concepts": [BIG + 100 + 8 * i + j for j in range(8)],
            "confidence": packs.CONFIDENCE[i % 3],
            "kind": kinds[i % len(kinds)],
            "text": text_of(width, f"reading {i + 1}"),
        }
        for i in range(count)
    ]


def _widest(make: Any, budget: int, top: int) -> Any:
    """The value with the longest text width (1..top) that fits the budget."""
    lo, hi = 1, top
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if packs.size_of(make(mid)) <= budget:
            lo = mid
        else:
            hi = mid - 1
    return make(lo)


def _facts(count: int) -> list[dict]:
    kinds = [k for k, (arg, _) in packs.FACTS.items() if arg == "concept"]
    rows = [{"arg": BIG + i, "kind": kinds[i % len(kinds)], "value": "yes"} for i in range(count)]
    rows = [{**r, "value": "small"} if r["kind"] == "has_data" else r for r in rows]
    return sorted(rows, key=lambda f: (f["kind"], f["arg"]))


def _block(budget: int, line_ids: list[str]) -> dict:
    hide = sorted(
        ({"from": "pid:" + f"{i:032x}", "line": line_ids[i % len(line_ids)]} for i in range(8)),
        key=lambda h: (h["from"], h["line"]),
    )
    people: list[str] = []
    for i in range(120):
        trial = sorted([*people, "person:" + hashlib.sha256(f"p{i}".encode()).hexdigest()])
        if packs.size_of({"hide": hide, "people": trial}) > budget:
            break
        people = trial
    return {"hide": hide, "people": people}


def _deny() -> dict:
    return {
        "domains": sorted(f"lab{i:02d}{'a' * 47}.example.org" for i in range(12)),
        "nodes": sorted(
            f"node-{hashlib.sha256(f'n{i}'.encode()).hexdigest()[:32]}" for i in range(10)
        ),
        "rors": sorted(f"0{i:06d}{i % 100:02d}" for i in range(10)),
    }


def base_pack(who: str, credential: dict, kind: str = "person", version: int = 7) -> dict:
    types = list(packs.GROUP_TYPES if kind == "group" else ["method_help", "research_fit"])
    return {
        "block": {"hide": [], "people": []},
        "charter": {
            "disclosure": "d0",
            "protocols": types,
            "rules": dict.fromkeys(types, "any"),
            "weekly_cap": 3,
        },
        "consent": {
            "approved_at": fmt_time(T0 - 10 * DAY),
            "descriptor_set": DESCRIPTOR_SET,
            "statement": STATEMENT_HASH,
        },
        "created": fmt_time(T0 - 600),
        "credential": credential,
        "deny": {"domains": [], "nodes": [], "rors": []},
        "expires": fmt_time(T0 - 600 + 30 * DAY),
        "facts": [],
        "kind": kind,
        "lines": {
            "offers": [
                {
                    "class": "instrument" if kind == "group" else "method",
                    "concepts": [101, 2044],
                    "id": "o01",
                    "scope": "both",
                    "text": "Single-particle cryo-EM data collection and map refinement",
                    "types": types[:1],
                }
            ],
            "wants": [
                {
                    "class": "data" if kind == "group" else "skill",
                    "concepts": [313],
                    "id": "w01",
                    "scope": "outside",
                    "text": "Molecular dynamics simulations of membrane transporters",
                    "types": types[:1],
                }
            ],
        },
        "readings": [],
        "reply_key": xpub(f"reply {who}").hex(),
        "schema": packs.SCHEMA,
        "subject": ed(who).public_bytes().hex(),
        "teasers": [],
        "topics": [101, 313, 2044],
        "version": version,
        "vocab": VOCAB,
    }


def fill_to_budget(doc: dict) -> dict:
    kind = doc["kind"]
    limits = packs.LIMITS[kind]
    b = limits.budgets
    types = list(packs.GROUP_TYPES) if kind == "group" else list(packs.TYPES)
    n = limits.lines
    doc["lines"] = _widest(
        lambda w: {"offers": _lines("o", n, w, types), "wants": _lines("w", n, w, types)},
        b["lines"],
        140,
    )
    doc["readings"] = _widest(lambda w: _readings(limits.readings, w), b["readings"], 200)
    doc["facts"] = _facts(150)
    doc["topics"] = [BIG + i for i in range(64)]
    doc["deny"] = _deny()
    ids = [x["id"] for x in doc["lines"]["offers"] + doc["lines"]["wants"]]
    doc["block"] = _block(b["block"], ids)
    doc["teasers"] = [text_of(100, f"teaser {i}") for i in range(3)]
    doc["charter"] = {
        "disclosure": "d0",
        "protocols": types,
        "rules": {t: packs.RULES[i % 3] for i, t in enumerate(types)},
        "weekly_cap": 3,
    }
    return doc


def context(roots: dict[int, bytes], teasers: bool = False) -> packs.Context:
    return packs.Context(
        now=T0,
        network=NETWORK,
        node_keys={NODE_A: ed("node A").public_bytes().hex()},
        log_roots=roots,
        descriptor_set=DESCRIPTOR_SET,
        statement=STATEMENT_HASH,
        teasers_allowed=teasers,
    )


def context_json(ctx: packs.Context) -> dict:
    return {
        "descriptor_set": ctx.descriptor_set,
        "formats": list(ctx.formats),
        "log_roots": {str(k): v.hex() for k, v in ctx.log_roots.items()},
        "network": ctx.network,
        "node_keys": ctx.node_keys,
        "now": fmt_time(ctx.now),
        "schemas": list(ctx.schemas),
        "statement": ctx.statement,
        "teasers_allowed": ctx.teasers_allowed,
    }


def join_salt(label: str) -> str:
    """A fixed salt for the join commitment of a vector credential."""
    return hashlib.sha256(f"join salt: {label}".encode()).hexdigest()[:32]


def credential_for(reuse: Reuse, label: str, facts: cred.MemberFacts, size: int = 0):
    """A first credential: its entry is the member's join entry
    (spec/network.md 6.5), at index 0 of a long proof or 4 of a small log."""
    raw = reuse.token(label, facts, ed("node A"), facts.issued + 60)
    salt = join_salt(label)
    entry = cred.log_entry(facts, raw, ed("node A"), cred.member_commit(facts.subject, salt))
    proof, root = long_proof(entry, size) if size else log_tree(entry)
    join = {"index": proof["index"], "salt": salt}
    proof = {"entry_signature": entry["signature"], "join": join, **proof}
    return {"format": cred.FORMAT_BISCUIT, "log": proof, "token": b64url(raw)}, proof, root


def _sizes(doc: dict) -> dict:
    out = {name: packs.size_of(doc[name]) for name in packs.LIMITS[doc["kind"]].budgets}
    out["total"] = len(canonical_json(doc))
    return out


def _signed(doc: dict, who: str) -> dict:
    return packs.sign_pack(doc, ed(who))


def refusals(small: dict, reuse: Reuse) -> list[dict]:
    """Each case: a body, the context changes, and the expected code."""
    alice = "alice"
    cases: list[tuple[str, bytes, str]] = []

    def resign(label: str, change: Any, code: str) -> None:
        doc = copy.deepcopy(small)
        change(doc)
        cases.append((label, canonical_json(_signed(doc, alice)), code))

    big = fill_to_budget(copy.deepcopy(small))
    while len(canonical_json(big)) <= packs.PACK_MAX:
        big["readings"].append(_readings(1, 200)[0])
    cases.append(("over_size", canonical_json(big), "too_large"))
    resign("field_over_budget", lambda d: d.update(readings=_readings(40, 200)), "too_large")
    resign("extra_field", lambda d: d.update(extra=1), "bad_message")
    bad_sig = copy.deepcopy(small)
    bad_sig["signature"] = "00" * 64
    cases.append(("bad_signature", canonical_json(bad_sig), "bad_signature"))
    resign("unknown_schema", lambda d: d.update(schema="anagram.pack.v2"), "unsupported_schema")
    resign(
        "deny_33",
        lambda d: d.update(
            deny={**_deny(), "rors": sorted(f"0{i:06d}{i % 100:02d}" for i in range(11))}
        ),
        "bad_message",
    )
    resign("topics_unsorted", lambda d: d.update(topics=[313, 101]), "bad_message")
    resign("control_char", lambda d: d["lines"]["offers"][0].update(text="a\u0007b"), "bad_message")
    resign("teaser_under_e1a", lambda d: d.update(teasers=["A teaser line"]), "bad_message")
    resign(
        "old_pack",
        lambda d: d.update(created=fmt_time(T0 - 3 * DAY), expires=fmt_time(T0 + 20 * DAY)),
        "expired",
    )
    resign("no_log_proof", lambda d: d["credential"].pop("log"), "bad_credential")
    exp = member_facts(alice, issued=T0 - 2 * DAY)
    exp_cred, _, _ = credential_for(reuse, "expired credential", exp)
    resign("expired_credential", lambda d: d.update(credential=exp_cred), "expired")
    other = member_facts("mallory")
    other_cred, _, _ = credential_for(reuse, "mallory credential", other)
    resign(
        "credential_of_another_subject", lambda d: d.update(credential=other_cred), "bad_credential"
    )
    cases.append(("float", canonical_json(small)[:-1] + b',"x":1.5}', "bad_message"))
    cases.append(("not_canonical", b" " + canonical_json(small), "bad_message"))
    return [
        {"body": body.decode("utf-8"), "code": code, "label": label} for label, body, code in cases
    ]


def build(reuse: Reuse) -> dict:
    alice = member_facts("alice")
    small_cred, _, small_root = credential_for(reuse, "alice credential", alice)
    roots = {small_cred["log"]["tree_size"]: small_root}
    small = _signed(base_pack("alice", small_cred), "alice")

    big_facts = member_facts("alice", tags=3)
    big_cred, big_proof, big_root = credential_for(
        reuse, "alice credential, 3 tags", big_facts, 2**32
    )
    roots[big_proof["tree_size"]] = big_root
    person = _signed(fill_to_budget(base_pack("alice", big_cred)), "alice")

    grp = member_facts("group A", kind="group")
    grp_cred, grp_proof, grp_root = credential_for(reuse, "group credential", grp, 2**32 - 1)
    roots[grp_proof["tree_size"]] = grp_root
    group = _signed(fill_to_budget(base_pack("group A", grp_cred, kind="group")), "group A")

    known_small = packs.encode_known(
        ed("alice"),
        3,
        T0 - 600,
        VOCAB,
        [
            (packs.known_tag(packs.person_id(ed("bob").public_bytes().hex())), [101, 313]),
            (packs.known_tag("pid:" + "3c" * 16), []),
            (packs.known_tag(packs.email_id(" Carol@Example.ORG ")), [7]),
        ],
    )
    known_full = full_known()
    out = {
        "description": "anagram.pack.v1 and anagram.known.v1 (spec/pack.md). Keys come from "
        "SHA-256('anagram net vector seed: <label>'). Biscuit tokens are random; a verifier "
        "checks them, and recomputes every other value.",
        "tags": [
            packs.TAG_SIGN,
            packs.TAG_KNOWN_SIGN,
            packs.TAG_KNOWN.decode(),
            packs.TAG_KNOWN_DAY,
        ],
        "seed_labels": seed_labels(
            alice="alice", group_a="group A", node_a="node A", reply_alice="reply alice"
        ),
        # T0 of the rules in pack.md 14 is the time of the pack context (`context.now`).
        "times": {"T0": fmt_time(T0)},
        "keys": {
            "alice": ed("alice").public_bytes().hex(),
            "group_a": ed("group A").public_bytes().hex(),
            "node_a": ed("node A").public_bytes().hex(),
        },
        "statement": STATEMENT,
        "statement_sha256": STATEMENT_HASH,
        "descriptors": {"documents": DESCRIPTORS, "set_hash": DESCRIPTOR_SET},
        "limits": {
            "pack_max": packs.PACK_MAX,
            "budgets": {k: v.budgets for k, v in packs.LIMITS.items()},
            "counts": {
                k: {"lines": v.lines, "readings": v.readings} for k, v in packs.LIMITS.items()
            },
        },
        "context": context_json(context(roots)),
        "small_pack": {"doc": small, "canonical_sha256": _sha(small)},
        "person_at_budget": {"doc": person, "sizes": _sizes(person), "context_teasers": True},
        "group_at_budget": {"doc": group, "sizes": _sizes(group), "context_teasers": True},
        "credential_log_entry": cred.log_entry(
            alice,
            cred.unb64url(small_cred["token"]),
            ed("node A"),
            cred.member_commit(alice.subject, small_cred["log"]["join"]["salt"]),
        ),
        "known_tags": known_tag_vectors(),
        "known_weekday": {
            "subject": "alice",
            "weekday": packs.known_weekday(ed("alice").public_bytes()),
        },
        "known_small": {"hex": known_small.hex(), "entries": 3},
        "known_full": {
            "rule": "entry i (0..4999): tag = known_tag('email:user<i>@example.org'), "
            "concepts = [i, i+1] for even i, else []; subject alice, version 9, created T0, "
            f"vocab {VOCAB}",
            "size": len(known_full),
            "sha256": hashlib.sha256(known_full).hexdigest(),
        },
        "refusals": refusals(small, reuse),
    }
    out["context"] = context_json(context(roots))
    return out


def full_known() -> bytes:
    entries = [
        (packs.known_tag(f"email:user{i}@example.org"), [i, i + 1] if i % 2 == 0 else [])
        for i in range(packs.KNOWN_MAX_ENTRIES)
    ]
    return packs.encode_known(ed("alice"), 9, T0, VOCAB, entries)


def known_tag_vectors() -> list[dict]:
    rows = [
        ("person", packs.person_id(ed("bob").public_bytes().hex())),
        ("pid", "pid:" + "3c" * 16),
        ("email", packs.email_id(" Carol@Example.ORG ")),
        ("email", packs.email_id(ALICE_EMAIL)),
    ]
    return [{"kind": k, "identifier": i, "tag": packs.known_tag(i).hex()} for k, i in rows]


def _sha(doc: dict) -> str:
    return hashlib.sha256(canonical_json(doc)).hexdigest()


__all__ = ["STATEMENT", "build"]
