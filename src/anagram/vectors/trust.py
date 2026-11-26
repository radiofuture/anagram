"""Test vectors for the trust policy (spec/trust.md). Fixed inputs only.
`anagram.vectors.build` writes them to spec/vectors/trust-policy.json."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from anagram.core.canonical import canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.local.trust.policy import (
    DISCOVERABLE,
    PRIVATE,
    SHARED,
    TRUST_TAGS,
    Peer,
    TrustPolicy,
    make_policy,
)

T0 = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)
OWNER = "pid:" + "5e" * 16
PEER = "pid:" + "6f" * 16
LAB_DENIED = "lab-" + "d1" * 8
LAB_ALLOWED = "lab-" + "a1" * 8


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"anagram trust vector seed: {label}".encode()).digest()


def _policy_doc(key: SigningKey) -> dict:
    return make_policy(
        owner=OWNER,
        rev=2,
        key=key,
        updated_at=T0,
        sources={"src-mail": DISCOVERABLE, "src-notes": SHARED, "src-diary": PRIVATE},
        folders={"src-notes": {"drafts/": PRIVATE}},
        items={"src-mail": {"msg-0007": PRIVATE}},
        allow={"labs": [LAB_ALLOWED], "communities": ["other.anagram.example"]},
        deny={
            "people": [PEER],
            "labs": [LAB_DENIED],
            "orgs": ["domain:rival.example", "ror:fake-rival"],
        },
    )


def _peer(case: dict) -> Peer:
    return Peer(
        pid=case.get("pid"),
        labs=frozenset(case.get("labs", ())),
        orgs=frozenset(case.get("orgs", ())),
        communities=frozenset(case.get("communities", ())),
    )


ITEM_CASES = [
    {"source": "src-mail", "key": "msg-0001", "third_party": False},
    {"source": "src-mail", "key": "msg-0007", "third_party": False},
    {"source": "src-mail", "key": "msg-0100", "third_party": True},
    {"source": "src-notes", "key": "drafts/a.md", "third_party": False},
    {"source": "src-notes", "key": "papers/b.md", "third_party": False},
    {"source": "src-diary", "key": "x", "third_party": False},
    {"source": "src-new", "key": "y", "third_party": False},
]

PEER_CASES = [
    {"pid": PEER, "in_scope": True},
    {"pid": "pid:" + "01" * 16, "labs": [LAB_ALLOWED], "in_scope": False},
    {"pid": "pid:" + "02" * 16, "labs": [LAB_ALLOWED, LAB_DENIED], "in_scope": False},
    {"pid": "pid:" + "03" * 16, "orgs": ["domain:rival.example"], "in_scope": True},
    {"pid": "pid:" + "04" * 16, "communities": ["other.anagram.example"], "in_scope": False},
    {"pid": "pid:" + "05" * 16, "in_scope": True},
    {"pid": "pid:" + "06" * 16, "in_scope": False},
]


def build() -> dict:
    key = SigningKey.from_seed(_seed("owner device"))
    doc = _policy_doc(key)
    policy = TrustPolicy.from_doc(doc)
    items = [
        {**c, "tier": policy.item_tier(c["source"], c["key"], third_party=c["third_party"])}
        for c in ITEM_CASES
    ]
    peers = [
        {**c, "reach": str(policy.reach(_peer(c), in_scope=c["in_scope"]))} for c in PEER_CASES
    ]
    return {
        "description": "Trust policy anagram.trust_policy.v1: a signed document, item "
        "tiers (the narrower wins; third-party items are private) and reach (deny wins).",
        "tags": list(TRUST_TAGS),
        "owner_seed": _seed("owner device").hex(),
        "owner_device": key.public_bytes().hex(),
        "document": doc,
        "signed_body_canonical": canonical_json(
            {k: v for k, v in doc.items() if k != "signature"}
        ).decode(),
        "items": items,
        "peers": peers,
        "room_blocks": policy.room_blocks(),
    }
