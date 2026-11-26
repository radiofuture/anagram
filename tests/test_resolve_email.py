"""R5 step 4a: find a member by email address (findable flag, rate limit,
audit, one 404 for all refusals)."""

from __future__ import annotations

import pytest
from conftest import make_net

from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.node.people import RESOLVES_PER_HOUR


def email_join(net, home, email):
    """Join with an email sign-in (the code comes from FakeMailer)."""

    def code():
        return net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]

    return net.join(home, None, email=email, email_code=code).client


@pytest.fixture
def world(tmp_path):
    net = make_net(tmp_path)
    chen = net.join(tmp_path / "chen", "fake-chen", "Chen").client
    return net, chen


def status_of(fn) -> int:
    with pytest.raises(NodeHTTPError) as exc:
        fn()
    return exc.value.status


def test_resolve_email_rules(world, tmp_path):
    net, chen = world
    okafor = email_join(net, tmp_path / "okafor", "Okafor@Uni.example")
    get = lambda e: chen.device.http.call("GET", f"/resolve/email/{e}", auth=True)  # noqa: E731
    # Not findable: the same 404 as an unknown address.
    assert status_of(lambda: get("okafor@uni.example")) == 404
    assert status_of(lambda: get("nobody@uni.example")) == 404
    assert status_of(lambda: get("not-an-address")) == 404
    okafor.account.set_findable(True)
    assert get("OKAFOR@uni.example")["subject"] == okafor.device.subject
    assert chen.shares.resolve_target("okafor@uni.example") == {
        "kind": "person",
        "label": "okafor@uni.example",
        "target": okafor.device.subject,
    }
    assert chen.shares.resolve_target("nobody@uni.example")["kind"] == "unknown_email"
    # The audit has a hash of the address, not the address.
    audit = net.identity.people.audit(chen.device.subject)
    assert all("uni.example" not in a["orcid"] for a in audit)
    assert [a["answered"] for a in audit][-2:] == [True, False]
    okafor.account.set_findable(False)
    assert status_of(lambda: get("okafor@uni.example")) == 404
    # No session: refused.
    assert status_of(lambda: net.transport("GET", "/resolve/email/okafor@uni.example", None)) == 401


def test_resolve_email_rate_limit_is_shared_with_orcid(world):
    net, chen = world
    for i in range(RESOLVES_PER_HOUR):
        try:
            chen.device.http.call("GET", f"/resolve/email/p{i}@x.example", auth=True)
        except NodeHTTPError:
            pass
    assert (
        status_of(lambda: chen.device.http.call("GET", "/resolve/orcid/fake-x", auth=True)) == 429
    )
    net.clock.t += 3601
    assert (
        status_of(lambda: chen.device.http.call("GET", "/resolve/email/p@x.example", auth=True))
        == 404
    )


def test_findable_needs_an_account(world, tmp_path):
    net, chen = world
    # An ORCID person can still turn findable on and off (the old answer key).
    # R8 adds the key `findable`; the old key stays for old clients.
    assert chen.account.set_findable(True) == {"findable": True, "findable_by_orcid": True}


def test_old_database_gets_the_column(tmp_path):
    import sqlite3

    net = make_net(tmp_path)
    db = sqlite3.connect(str(net.home.dir / "identity.sqlite"))
    cols = {r[1] for r in db.execute("PRAGMA table_info(email_accounts)")}
    assert "findable" in cols
