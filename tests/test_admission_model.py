"""The admission model (layer L4): one policy function for each kind of
invite, a node policy, and group rules that can only narrow it."""

from datetime import UTC, datetime, timedelta

import pytest

from anagram.admission.model import (
    CONTACT,
    ENDORSER,
    EXPIRED,
    GROUP,
    NODE,
    READER,
    REVOKED,
    USED,
    Claim,
    Endorsement,
    NodePolicy,
    Vouch,
    endorser_may,
    invite_only,
)

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def endorsement(**kw) -> Endorsement:
    base = {
        "kind": NODE,
        "ref": "i1",
        "endorser": None,
        "role": "member",
        "max_uses": 1,
        "uses": 0,
        "expires_at": NOW + timedelta(days=1),
    }
    return Endorsement(**{**base, **kw})


def test_invite_only_admits_an_open_invite():
    assert invite_only(endorsement(), Claim(at=NOW)) is None


def test_invite_only_checks_in_a_fixed_order():
    late = NOW + timedelta(days=2)
    every = endorsement(revoked=True, uses=1, contact=("email", "a@b.org"))
    assert invite_only(every, Claim(at=late)) == REVOKED
    assert invite_only(endorsement(uses=1), Claim(at=late)) == USED
    assert invite_only(endorsement(), Claim(at=late)) == EXPIRED
    assert invite_only(endorsement(expires_at=NOW), Claim(at=NOW)) is None  # the last second


def test_a_reader_invite_needs_the_contact_proof():
    e = endorsement(kind=READER, contact=("email", "a@b.org"))
    assert invite_only(e, Claim(at=NOW)) == CONTACT
    assert invite_only(e, Claim(at=NOW, proved_contact=True)) is None


def test_a_group_rule_can_only_narrow_the_node_policy():
    policy = NodePolicy()
    e = endorsement(kind=GROUP, max_uses=5)
    assert policy.decide(e, Claim(at=NOW), narrow=(endorser_may(True),)) is None
    assert policy.decide(e, Claim(at=NOW), narrow=(endorser_may(False),)) == ENDORSER
    # The node refusal stays when the group rule would admit.
    used = endorsement(kind=GROUP, uses=5, max_uses=5)
    assert policy.decide(used, Claim(at=NOW), narrow=(lambda e, c: None,)) == USED


def test_a_later_policy_is_a_new_function():
    def open_entry(e, c):
        return None

    policy = NodePolicy(admit=open_entry)
    assert policy.decide(endorsement(uses=1), Claim(at=NOW)) is None


def test_the_group_create_rule():
    with pytest.raises(ValueError):
        NodePolicy(create_group="anyone")
    strict, open_ = NodePolicy(), NodePolicy(create_group="member")
    assert strict.may_create_group(False, Vouch(NODE, None))
    assert strict.may_create_group(True, Vouch(GROUP, "pid:x"))
    assert not strict.may_create_group(False, Vouch(GROUP, "pid:x"))
    assert not strict.may_create_group(False, Vouch(READER, "pid:x"))
    assert open_.may_create_group(False, Vouch(READER, "pid:x"))
