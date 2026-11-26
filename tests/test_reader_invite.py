"""R5 step 4c: invite a person who is not a member to read a finding (plan
section 6.5, decision P10). The person joins the node with the contact of the
invite, has no lab, and reads the finding after one owner sync. FakeMailer
and FakeOrcid; no network."""

from __future__ import annotations

import re

import pytest
from sharekit import commit, make_share_net, people

from anagram.admission.formats import parse_invite_url
from anagram.admission.node import reader as ri
from anagram.core.errors import ClientError, NodeError, RateLimited
from anagram.core.nodeapi import NodeHTTPError

CLAIM = "Growth doubles at 37 degrees\nThe secret detail of the result."


@pytest.fixture
def world(tmp_path):
    net = make_share_net(tmp_path)
    chen = people(net, tmp_path, "chen")["chen"]
    chen.account.set_identity("Dr. Chen")
    root = commit(chen, tmp_path, {"plan.md": b"# Plan\nGrow cells."}, claim=CLAIM)
    return net, chen, root


def email_join(net, home, email, link):
    """Join with an email sign-in and this invite link."""

    def code():
        texts = [t for _, _, t in net.mailer.outbox if "sign-in code is" in t]
        return re.search(r"code is (\d{8})", texts[-1]).group(1)

    return net.join(home, None, email=email, email_code=code, invite=link)


def status_of(fn) -> int:
    with pytest.raises(NodeHTTPError) as exc:
        fn()
    return exc.value.status


def test_invite_by_email_joins_with_no_lab_and_reads_after_one_sync(world, tmp_path):
    net, chen, root = world
    out = chen.invites.invite_reader(root, "Dana@Uni.example")
    assert out["mailed"] is True and out["link"].startswith("http")
    assert set(out) == {"invite_id", "link", "mailed", "expires_at"}
    to, subject, text = net.mailer.outbox[-1]
    assert to == "dana@uni.example"
    assert out["link"] in text and "Dr. Chen shared a finding with you" in text
    fid = chen.vault.get(root).finding_id
    (sh,) = chen.share_store.shares_of(fid)
    assert sh["target"] == f"invite:{out['invite_id']}" and sh["state"] == "active"
    # No grant yet: there is no key of the person.
    assert chen.vault.grants_sent(root) == []
    assert chen.invites.sync_reader_invites() == []  # not claimed yet

    dana = email_join(net, tmp_path / "dana", "dana@uni.example", out["link"]).client
    assert net.identity.is_member(dana.device.subject)
    assert net.labs.directory.labs_of(dana.device.subject) == []
    (invite,) = net.identity._one(
        "SELECT invite FROM members WHERE subject = ?", dana.device.subject
    )
    assert invite == f"reader:{out['invite_id']}"
    # The new member cannot start a lab on a node with the organizer rule.
    assert net.admission.policy.create_group == "organizer_invite"
    assert net.labs.may_create(dana.device.subject) is False
    assert net.labs.may_create(chen.device.subject) is True
    # The reader sees who shared before the grant comes.
    assert dana.received.reader_invites_mine() == [
        {"invite_id": out["invite_id"], "owner": chen.device.subject}
    ]

    # Security review P1-3: the owner confirms the claimer before the grant.
    (ask,) = chen.invites.sync_reader_invites()
    assert ask == {"findings": [], "invite_id": out["invite_id"], "kind": "confirm",
                   "subject": dana.device.subject}  # fmt: skip
    assert chen.vault.grants_sent(root) == [] and dana.grants.inbox() == []
    assert chen.invites.sync_reader_invites() == []  # one question, not one for each sync
    (claim,) = chen.invites.reader_claims()
    assert claim["email"] == "dana@uni.example" and claim["subject"] == dana.device.subject
    assert claim["contact"] == {"kind": "email", "value": "dana@uni.example"}
    changed = chen.invites.confirm_reader_claim(out["invite_id"], True)["changed"]
    assert chen.invites.reader_claims() == []
    assert changed == [
        {
            "findings": [fid],
            "invite_id": out["invite_id"],
            "kind": "shared",
            "subject": dana.device.subject,
        }
    ]
    (sh,) = chen.share_store.shares_of(fid)
    assert sh["target"] == dana.device.subject and sh["state"] == "active"
    kinds = [(e["kind"], e["person"]) for e in chen.share_store.share_events(finding_id=fid)]
    assert kinds == [("invite_sent", dana.device.subject), ("shared", dana.device.subject)]
    (g,) = dana.grants.inbox()
    model = dana.received.open_received(g["grant_id"])
    assert model["claim"] == CLAIM and model["root"] == root
    # A second sync does nothing more.
    assert chen.invites.sync_reader_invites() == []
    assert len(chen.vault.grants_sent(root)) == 1


def test_invite_by_orcid_needs_an_orcid_sign_in(world, tmp_path):
    net, chen, root = world
    n_mail = len(net.mailer.outbox)
    out = chen.invites.invite_reader(root, "orcid:fake-erin")
    assert out["mailed"] is False and len(net.mailer.outbox) == n_mail  # the owner sends it
    erin = net.join(tmp_path / "erin", "fake-erin", "Erin", invite=out["link"]).client
    assert net.labs.directory.labs_of(erin.device.subject) == []
    assert chen.invites.sync_reader_invites()[0]["subject"] == erin.device.subject
    chen.invites.confirm_reader_claim(out["invite_id"], True)
    (g,) = erin.grants.inbox()
    assert erin.received.open_received(g["grant_id"])["root"] == root


def test_a_forwarded_link_is_refused_and_makes_no_member(world, tmp_path):
    net, chen, root = world
    out = chen.invites.invite_reader(root, "dana@uni.example")
    with pytest.raises(NodeHTTPError) as exc:
        email_join(net, tmp_path / "eve", "eve@other.example", out["link"])
    assert exc.value.status == 404
    eve = net.identity._one(
        "SELECT subject FROM email_accounts WHERE email = ?", "eve@other.example"
    )[0]
    assert not net.identity.is_member(eve)
    # An ORCID sign-in of another person fails the same way.
    with pytest.raises(NodeHTTPError) as exc:
        net.join(tmp_path / "frank", "fake-frank", "Frank", invite=out["link"])
    assert exc.value.status == 404
    # The right person still can join with it, and then nobody else can.
    dana = email_join(net, tmp_path / "dana", "dana@uni.example", out["link"]).client
    assert net.identity.is_member(dana.device.subject)
    with pytest.raises(NodeHTTPError) as exc:
        email_join(net, tmp_path / "eve2", "eve@other.example", out["link"])
    assert exc.value.status == 404


def test_the_answer_is_the_same_for_a_member_an_account_and_a_new_address(world, tmp_path):
    net, chen, root = world
    member = email_join(net, tmp_path / "m", "member@uni.example", net.invite()).client
    net.identity.db.execute(
        "INSERT INTO email_accounts (email, subject) VALUES (?, ?)",
        ("account@uni.example", "pid:" + "1" * 32),
    )
    answers = []
    for email in ("member@uni.example", "account@uni.example", "new@uni.example"):
        r = chen.device.http.call(
            "POST", "/reader-invites", {"contact": {"kind": "email", "value": email}}, auth=True
        )
        answers.append(r)
    assert all(set(a) == {"expires_at", "invite_id", "invite_url", "mailed"} for a in answers)
    assert [a["mailed"] for a in answers] == [True, True, True]
    assert all(a["invite_url"] for a in answers)
    # The owner learns no pid before the claim.
    listed = chen.device.http.call("GET", "/reader-invites", None, auth=True)["invites"]
    assert [i["subject"] for i in listed] == [None, None, None]
    # A member claims from the app: the claim is idempotent and the member
    # keeps the role and invite of before.
    token = parse_invite_url(answers[0]["invite_url"])["token"]
    for _ in range(2):
        member.device.http.call("POST", "/invites/claim", {"token": token}, auth=True)
    (inv,) = net.identity._one(
        "SELECT invite FROM members WHERE subject = ?", member.device.subject
    )
    assert not inv.startswith("reader:")
    claimed = chen.device.http.call("GET", "/reader-invites?state=claimed", None, auth=True)[
        "invites"
    ]
    assert [i["subject"] for i in claimed] == [member.device.subject]


def test_the_mail_has_no_text_of_the_owner_and_no_title(world):
    net, chen, root = world
    chen.invites.invite_reader(root, "dana@uni.example")
    to, subject, text = net.mailer.outbox[-1]
    assert "Growth doubles" not in subject + text and "secret detail" not in subject + text
    link = re.search(r"(http\S+/join#\S+)", text).group(1)
    assert text == ri.MAIL_TEXT.format(name="Dr. Chen", community="Test community", link=link)
    assert subject == ri.MAIL_SUBJECT.format(community="Test community")


def test_one_open_invite_for_each_contact_covers_more_findings(world, tmp_path):
    net, chen, root = world
    root2 = commit(chen, tmp_path, {"b.md": b"# B\nMore."}, claim="Second result")
    a = chen.invites.invite_reader(root, "dana@uni.example")
    n_mail = len(net.mailer.outbox)
    b = chen.invites.invite_reader(root2, "dana@uni.example")
    assert b["invite_id"] == a["invite_id"] and b["link"] == a["link"]
    assert len(net.mailer.outbox) == n_mail  # no second mail
    # The node gives no second link for the same contact.
    again = chen.device.http.call(
        "POST",
        "/reader-invites",
        {"contact": {"kind": "email", "value": "dana@uni.example"}},
        auth=True,
    )
    assert again["invite_id"] == a["invite_id"] and again["invite_url"] is None
    dana = email_join(net, tmp_path / "dana", "dana@uni.example", a["link"]).client
    chen.invites.sync_reader_invites()
    (changed,) = chen.invites.confirm_reader_claim(a["invite_id"], True)["changed"]
    assert len(changed["findings"]) == 2
    assert sorted(g["root"] for g in chen.vault.grants_sent()) == sorted([root, root2])
    assert len(dana.grants.inbox()) == 2


def test_rate_limits(world, tmp_path):
    net, chen, root = world
    inv = net.reader_invites
    made = [
        inv.create(chen.device.subject, {"kind": "email", "value": f"p{i}@x.example"})
        for i in range(ri.OPEN_MAX)
    ]
    with pytest.raises(RateLimited):
        inv.create(chen.device.subject, {"kind": "email", "value": "one-more@x.example"})
    for m in made:
        inv.revoke(chen.device.subject, m["invite_id"])
    for i in range(ri.DAY_MAX - ri.OPEN_MAX):
        m = inv.create(chen.device.subject, {"kind": "orcid", "value": f"fake-p{i}"})
        inv.revoke(chen.device.subject, m["invite_id"])
    with pytest.raises(RateLimited):
        inv.create(chen.device.subject, {"kind": "email", "value": "late@x.example"})
    net.clock.t += 86401
    inv.create(chen.device.subject, {"kind": "email", "value": "next-day@x.example"})
    for bad in ({"kind": "email", "value": "no-at"}, {"kind": "phone", "value": "1"},
                {"kind": "orcid", "value": "0000-0000"}, "dana@x.example"):  # fmt: skip
        with pytest.raises(NodeError):
            inv.create(chen.device.subject, bad)
    with pytest.raises(NodeError):
        inv.create(chen.device.subject, {"kind": "email", "value": "a@b.example"}, 31)


def test_revoke_before_the_claim(world, tmp_path):
    net, chen, root = world
    out = chen.invites.invite_reader(root, "dana@uni.example")
    fid = chen.vault.get(root).finding_id
    stopped = chen.shares.stop_sharing(root, f"invite:{out['invite_id']}")
    assert stopped["target"] == f"invite:{out['invite_id']}"
    (sh,) = chen.share_store.shares_of(fid)
    assert sh["state"] == "stopped"
    states = chen.device.http.call("GET", "/reader-invites", None, auth=True)["invites"]
    assert [i["state"] for i in states] == ["revoked"]
    with pytest.raises(NodeHTTPError) as exc:
        email_join(net, tmp_path / "dana", "dana@uni.example", out["link"])
    assert exc.value.status == 404
    assert chen.invites.sync_reader_invites() == []
    assert chen.vault.grants_sent(root) == []


def test_an_expired_invite_gives_invite_expired(world, tmp_path):
    net, chen, root = world
    out = chen.invites.invite_reader(root, "dana@uni.example", expires_days=1)
    fid = chen.vault.get(root).finding_id
    net.clock.t += 2 * 86400
    (changed,) = chen.invites.sync_reader_invites()
    assert changed["kind"] == "invite_expired" and changed["findings"] == [fid]
    (sh,) = chen.share_store.shares_of(fid)
    assert sh["state"] == "stopped"
    assert [e["kind"] for e in chen.share_store.share_events(finding_id=fid)] == [
        "invite_sent",
        "invite_expired",
    ]
    with pytest.raises((NodeHTTPError, ClientError)):
        email_join(net, tmp_path / "dana", "dana@uni.example", out["link"])
    assert chen.invites.sync_reader_invites() == []


def test_only_the_owner_sees_and_ends_an_invite(world, tmp_path):
    net, chen, root = world
    other = people(net, tmp_path, "okafor")["okafor"]
    out = chen.invites.invite_reader(root, "dana@uni.example")
    assert other.device.http.call("GET", "/reader-invites", None, auth=True) == {"invites": []}
    assert (
        status_of(
            lambda: other.device.http.call(
                "DELETE", f"/reader-invites/{out['invite_id']}", None, auth=True
            )
        )
        == 404
    )
    # No session: no invite.
    r = net.tc.post("/reader-invites", json={"contact": {"kind": "email", "value": "a@b.example"}})
    assert r.status_code == 401


# ------------------------------------------- security review P1-3


def test_a_node_that_marks_a_claim_gets_no_key_without_the_owner(world, tmp_path):
    """A node that breaks the rules marks the invite as claimed by a person
    that it controls. The owner's client asks first; a "no" stops the share
    and no key goes. (Before R8 the client granted at once.)"""
    net, chen, root = world
    out = chen.invites.invite_reader(root, "dana@uni.example")
    fid = chen.vault.get(root).finding_id
    mallory = net.join_invite(tmp_path / "mallory", "Dana").client  # the node's own person
    net.identity.db.execute(
        "UPDATE reader_invites SET state = 'claimed', subject = ? WHERE invite_id = ?",
        (mallory.device.subject, out["invite_id"]),
    )
    (ask,) = chen.invites.sync_reader_invites()
    assert ask["kind"] == "confirm" and ask["subject"] == mallory.device.subject
    assert chen.vault.grants_sent(root) == []
    (claim,) = chen.invites.reader_claims()
    assert claim["name"] == "Dana" and claim["email"] is None  # no proved address
    got = chen.invites.confirm_reader_claim(out["invite_id"], False)
    assert got == {"findings": [fid], "given": False, "invite_id": out["invite_id"]}
    assert chen.vault.grants_sent(root) == [] and mallory.grants.inbox() == []
    (sh,) = chen.share_store.shares_of(fid)
    assert sh["state"] == "stopped"
    assert chen.invites.sync_reader_invites() == [] and chen.invites.reader_claims() == []
    with pytest.raises(ClientError):
        chen.invites.confirm_reader_claim(out["invite_id"], True)


def test_only_the_named_claimer_is_confirmed(world, tmp_path):
    """A yes is for one person: if the node names another person later, the
    owner is asked again."""
    net, chen, root = world
    out = chen.invites.invite_reader(root, "dana@uni.example")
    a = net.join_invite(tmp_path / "a", "Person A").client
    b = net.join_invite(tmp_path / "b", "Person B").client
    net.identity.db.execute(
        "UPDATE reader_invites SET state = 'claimed', subject = ? WHERE invite_id = ?",
        (a.device.subject, out["invite_id"]),
    )
    chen.invites.sync_reader_invites()
    net.identity.db.execute(
        "UPDATE reader_invites SET subject = ? WHERE invite_id = ?",
        (b.device.subject, out["invite_id"]),
    )
    (ask,) = chen.invites.sync_reader_invites()
    assert ask["subject"] == b.device.subject
    (claim,) = chen.invites.reader_claims()
    assert claim["name"] == "Person B"
    assert chen.vault.grants_sent(root) == []
