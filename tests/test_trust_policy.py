"""The trust policy (plan net 05 step 1, spec/trust.md): format, signature,
tiers (the narrower wins), reach (deny wins), store, vectors, speed."""

from __future__ import annotations

import copy
import json
import random
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from indexkit import KEY

from anagram.core.crypto.hashing import ALL_TAGS
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import FormatError
from anagram.local.index.store import IndexStore
from anagram.local.trust.policy import (
    COMMUNITIES,
    DISCOVERABLE,
    LABS,
    MAX_MARKS,
    MAX_SUBJECTS,
    ORGS,
    PEOPLE,
    PRIVATE,
    SHARED,
    TIERS,
    TRUST_TAGS,
    Peer,
    Reach,
    TrustPolicy,
    make_policy,
    mutual_deny,
    narrowest,
    reading_tier,
    validate_policy,
    verify_policy,
)
from anagram.local.trust.store import TrustStore

VEC = json.loads(
    (Path(__file__).parent.parent / "spec" / "vectors" / "trust-policy.json").read_text()
)
T0 = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)
OWNER = "pid:" + "aa" * 16
OTHER = "pid:" + "bb" * 16


def _key(label: str) -> SigningKey:
    return SigningKey.from_seed(label.encode().ljust(32, b"\0")[:32])


DEVICE = _key("owner device")
STRANGER = _key("another person")


def _pid(n: int) -> str:
    return f"pid:{n:032x}"


def _lab(n: int) -> str:
    return f"lab-{n:016x}"


def _org(n: int) -> str:
    return f"domain:org{n}.example" if n % 2 else f"ror:fake-org-{n}"


def _host(n: int) -> str:
    return f"c{n}.anagram.example"


_MAKERS = {PEOPLE: _pid, LABS: _lab, ORGS: _org, COMMUNITIES: _host}


# ------------------------------------------------------------------ vectors


def test_vector_document_verifies_and_recomputes():
    doc = VEC["document"]
    device = bytes.fromhex(VEC["owner_device"])
    verify_policy(doc, [device])
    assert SigningKey.from_seed(bytes.fromhex(VEC["owner_seed"])).public_bytes() == device
    policy = TrustPolicy.from_doc(doc)
    for c in VEC["items"]:
        got = policy.item_tier(c["source"], c["key"], third_party=c["third_party"])
        assert got == c["tier"], c
    for c in VEC["peers"]:
        peer = Peer(
            pid=c.get("pid"),
            labs=frozenset(c.get("labs", ())),
            orgs=frozenset(c.get("orgs", ())),
            communities=frozenset(c.get("communities", ())),
        )
        assert policy.reach(peer, in_scope=c["in_scope"]) == c["reach"], c
    assert policy.room_blocks() == VEC["room_blocks"]


def test_trust_tags_are_new():
    assert VEC["tags"] == list(TRUST_TAGS)
    assert not set(TRUST_TAGS) & set(ALL_TAGS)


# ------------------------------------------------------------------- format


def _doc(**kw) -> dict:
    base = {"owner": OWNER, "rev": 1, "key": DEVICE, "updated_at": T0}
    return make_policy(**{**base, **kw})


def test_signature_and_signer_are_checked():
    doc = _doc(deny={"labs": [_lab(1)]})
    verify_policy(doc, [DEVICE.public_bytes()])
    changed = copy.deepcopy(doc)
    changed["deny"]["labs"] = []  # a wider policy, with the old signature
    with pytest.raises(FormatError, match="bad signature"):
        verify_policy(changed, [DEVICE.public_bytes()])
    with pytest.raises(FormatError, match="not a device of the owner"):
        verify_policy(doc, [STRANGER.public_bytes()])


def test_another_person_cannot_sign_my_policy():
    forged = make_policy(owner=OWNER, rev=9, key=STRANGER, updated_at=T0, own_default=SHARED)
    with pytest.raises(FormatError):
        verify_policy(forged, [DEVICE.public_bytes()])


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("defaults", "own"), "public"),
        (("sources",), {"s": "open"}),
        (("items",), {"s": {}}),
        (("deny", "labs"), [_lab(2), _lab(1)]),
        (("deny", "labs"), [_lab(1), _lab(1)]),
        (("deny", "orgs"), ["example.org"]),
        (("allow", "communities"), ["Not A Host"]),
        (("rev",), 0),
        (("schema",), "anagram.trust_policy.v2"),
    ],
)
def test_bad_forms_are_refused(path, value):
    doc = _doc()
    target = doc
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    with pytest.raises(FormatError):
        validate_policy(doc)


def test_limits():
    with pytest.raises(FormatError):
        _doc(deny={"people": [_pid(n) for n in range(MAX_SUBJECTS + 1)]})
    with pytest.raises(FormatError):
        _doc(items={"s": {f"k{n}": PRIVATE for n in range(MAX_MARKS + 1)}})


# -------------------------------------------------------------------- tiers


def test_default_policy_is_decision_n5():
    """Own items in all sources are discoverable; items of other people are
    private, also when the person marks their source shared."""
    policy = TrustPolicy.default(OWNER)
    for sid in ("gmail", "gdrive", "notes", "folder", "github", "orcid"):
        assert policy.item_tier(sid, "own", third_party=False) == DISCOVERABLE
        assert policy.item_tier(sid, "theirs", third_party=True) == PRIVATE
    marked = TrustPolicy.from_doc(_doc(sources={"gmail": SHARED}, items={"gmail": {"k": SHARED}}))
    assert marked.item_tier("gmail", "k", third_party=True) == PRIVATE


def test_person_can_mark_a_source_or_folder_private():
    policy = TrustPolicy.from_doc(
        _doc(sources={"diary": PRIVATE}, folders={"drive": {"personal/": PRIVATE}})
    )
    assert policy.item_tier("diary", "a", third_party=False) == PRIVATE
    assert policy.item_tier("drive", "personal/tax.pdf", third_party=False) == PRIVATE
    assert policy.item_tier("drive", "papers/p.pdf", third_party=False) == DISCOVERABLE


def _random_marks(rng: random.Random) -> dict:
    sids = [f"s{n}" for n in range(4)]
    return {
        "own_default": rng.choice(TIERS),
        "sources": {s: rng.choice(TIERS) for s in sids if rng.random() < 0.5},
        "folders": {s: {f"f{n}/": rng.choice(TIERS) for n in range(2)} for s in sids[:2]},
        "items": {s: {f"f{n}/k": rng.choice(TIERS) for n in range(3)} for s in sids[1:3]},
    }


def test_property_narrower_tier_wins():
    """1,000 random policies: the item tier is the narrowest of source (or
    default), each holding folder, and the item mark; never wider than any
    of them. A reading is never wider than its narrowest basis item."""
    rng = random.Random(5)  # noqa: S311 - test data
    for _ in range(1000):
        marks = _random_marks(rng)
        policy = TrustPolicy.from_doc(_doc(**marks))
        sid = rng.choice(["s0", "s1", "s2", "s3"])
        key = f"f{rng.randrange(3)}/k"
        expected = [marks["sources"].get(sid, marks["own_default"])]
        expected += [t for p, t in marks["folders"].get(sid, {}).items() if key.startswith(p)]
        if key in marks["items"].get(sid, {}):
            expected.append(marks["items"][sid][key])
        got = policy.item_tier(sid, key, third_party=False)
        assert got == narrowest(expected)
        assert all(TIERS.index(got) <= TIERS.index(t) for t in expected)
        basis = [rng.choice(TIERS) for _ in range(rng.randrange(1, 6))]
        assert TIERS.index(reading_tier(basis)) == min(TIERS.index(t) for t in basis)
    assert reading_tier([]) == PRIVATE


# -------------------------------------------------------------------- reach


def _random_subjects(rng: random.Random, pool: int) -> dict:
    return {
        k: [m(rng.randrange(pool)) for _ in range(rng.randrange(4))] for k, m in _MAKERS.items()
    }


def _random_peer(rng: random.Random, pool: int) -> Peer:
    return Peer(
        pid=_pid(rng.randrange(pool)),
        labs=frozenset(_lab(rng.randrange(pool)) for _ in range(rng.randrange(3))),
        orgs=frozenset(_org(rng.randrange(pool)) for _ in range(rng.randrange(3))),
        communities=frozenset(_host(rng.randrange(pool)) for _ in range(rng.randrange(2))),
    )


def test_property_deny_wins():
    """1,000 random policies and subjects (a small ID pool, so many peers
    match both lists): deny wins in 100 % of the conflicts."""
    rng = random.Random(11)  # noqa: S311 - test data
    conflicts = denied = 0
    for _ in range(1000):
        policy = TrustPolicy.from_doc(
            _doc(allow=_random_subjects(rng, 6), deny=_random_subjects(rng, 6))
        )
        peer = _random_peer(rng, 6)
        in_scope = rng.random() < 0.5
        reach = policy.reach(peer, in_scope=in_scope)
        if policy.denies(peer):
            assert reach == Reach.DENIED
            assert not policy.may_reach(peer, in_scope=in_scope)
            denied += 1
            conflicts += policy.allows(peer)
        elif policy.allows(peer):
            assert reach == Reach.ALLOWED
        else:
            assert reach == (Reach.IN_SCOPE if in_scope else Reach.OUT_OF_SCOPE)
    assert conflicts >= 100, conflicts  # the test covers enough conflicts
    print(f"deny wins: {conflicts} of {conflicts} conflicts ({denied} denied of 1000)")


def test_allow_widens_only_across_a_boundary():
    policy = TrustPolicy.from_doc(_doc(allow={"labs": [_lab(1)]}))
    inside = Peer(pid=_pid(1))
    allowed = Peer(pid=_pid(2), labs=frozenset({_lab(1)}))
    assert policy.may_reach(inside, in_scope=True)
    assert not policy.may_reach(inside, in_scope=False)
    assert policy.may_reach(allowed, in_scope=False)


def test_allow_of_one_side_never_cancels_deny_of_the_other():
    a = TrustPolicy.from_doc(_doc(deny={"orgs": ["domain:rival.example"]}))
    b_owner_device = _key("b device")
    b = TrustPolicy.from_doc(
        make_policy(
            owner=OTHER,
            rev=1,
            key=b_owner_device,
            updated_at=T0,
            allow={"people": [OWNER]},
        )
    )
    b_seen_by_a = Peer(pid=OTHER, orgs=frozenset({"domain:rival.example"}))
    a_seen_by_b = Peer(pid=OWNER)
    assert b.may_reach(a_seen_by_b, in_scope=False)
    assert mutual_deny(a, b_seen_by_a, b, a_seen_by_b)


# -------------------------------------------------------------------- store


def test_store_default_save_rollback_and_history(tmp_path):
    store = IndexStore(tmp_path / "i.sqlite", KEY)
    trust = TrustStore(store, OWNER, [DEVICE.public_bytes()])
    assert trust.current() == TrustPolicy.default(OWNER)
    trust.save(_doc(rev=1, deny={"labs": [_lab(1)]}))
    trust.save(_doc(rev=2, deny={"labs": [_lab(1), _lab(2)]}))
    with pytest.raises(FormatError, match="rev"):
        trust.save(_doc(rev=2))
    with pytest.raises(FormatError):
        trust.save(make_policy(owner=OTHER, rev=3, key=DEVICE, updated_at=T0))
    with pytest.raises(FormatError):
        trust.save(make_policy(owner=OWNER, rev=3, key=STRANGER, updated_at=T0))
    assert trust.current().rev == 2
    assert [d["rev"] for d in trust.history()] == [1]
    store.close()
    again = TrustStore(IndexStore(tmp_path / "i.sqlite", KEY), OWNER, [DEVICE.public_bytes()])
    assert again.current().denies(Peer(labs=frozenset({_lab(2)})))


def test_store_refuses_a_changed_saved_document(tmp_path):
    store = IndexStore(tmp_path / "i.sqlite", KEY)
    trust = TrustStore(store, OWNER, [DEVICE.public_bytes()])
    trust.save(_doc(rev=1, deny={"labs": [_lab(1)]}))
    doc = trust.document()
    doc["deny"]["labs"] = []  # a wider policy, written past the store
    store.set_meta("trust_policy", doc)
    with pytest.raises(FormatError):
        trust.current()


# -------------------------------------------------------------------- speed


def test_evaluation_p95_under_1_ms():
    """A policy at the limits (256 subjects of each kind in allow and in
    deny, 10,000 marks): one item tier and one reach together, p95 <= 1 ms."""
    rng = random.Random(3)  # noqa: S311 - test data
    full = {k: [m(n) for n in range(MAX_SUBJECTS)] for k, m in _MAKERS.items()}
    other = {k: [m(n + 10_000) for n in range(MAX_SUBJECTS)] for k, m in _MAKERS.items()}
    items = {f"s{n}": {f"d/{i}": rng.choice(TIERS) for i in range(990)} for n in range(10)}
    folders = {f"s{n}": {f"d{i}/": PRIVATE for i in range(9)} for n in range(10)}
    policy = TrustPolicy.from_doc(_doc(allow=other, deny=full, items=items, folders=folders))
    times = []
    for n in range(2000):
        peer = _random_peer(rng, 20_000)
        start = time.perf_counter()
        policy.item_tier(f"s{n % 10}", f"d/{n % 990}", third_party=False)
        policy.reach(peer, in_scope=bool(n % 2))
        times.append(time.perf_counter() - start)
    times.sort()
    p95_ms = times[int(0.95 * len(times))] * 1000
    print(f"trust evaluation p95 {p95_ms:.4f} ms, max {times[-1] * 1000:.4f} ms")
    assert p95_ms <= 1.0
