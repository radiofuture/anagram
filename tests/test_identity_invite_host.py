"""R8: the node side of identity without ORCID.

The invite is the proof of a person. A stated email address is never a
sign-in address. An ORCID iD is optional and can be linked later.
"""

import secrets

import pytest

from anagram.admission.formats import parse_invite_url
from anagram.admission.node.reader import ReaderInvites
from anagram.admission.node.store import AdmissionStore
from anagram.core.crypto.signing import SigningKey
from anagram.core.crypto.x25519 import X25519Key
from anagram.core.errors import Conflict, Forbidden, Gone, NotFound
from anagram.identity.formats.documents import (
    device_json,
    make_binding,
    sign_possession,
    verify_assertion,
)
from anagram.identity.node.email_signin import mask_email


def _token(net, days=7, created_by=None):
    url = net.admission.create_invite(created_by, days)["invite_url"]
    return parse_invite_url(url)["token"]


def _dev():
    key = SigningKey.from_seed(secrets.token_bytes(32))
    return key, device_json(key.public_bytes(), X25519Key.generate().public_bytes())


def _post(net, path, body, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return net.tc.post(path, json=body, headers=headers)


def _signin(net, invite, key, email=None, pid=None):
    body = {
        "device_key": key.public_bytes().hex(),
        "invite": invite,
        "nonce": secrets.token_hex(16),
    }
    if email is not None:
        body["email"] = email
    if pid is not None:
        body["pid"] = pid
    return _post(net, "/auth/invite", body)


def test_invite_signin_makes_a_member_with_no_orcid(net):
    key, dev = _dev()
    r = _signin(net, _token(net), key, email="Ada@Lab.org", pid="pid:" + "ab" * 16)
    assert r.status_code == 200, r.text
    out = r.json()
    a = verify_assertion(
        out["assertion"], assertion_key=net.identity.key.public_bytes(),
        node_key=net.identity.cfg.node_key, audience=key.public_bytes(),
    )  # fmt: skip
    assert a["method"] == "invite" and a["orcid_commitment"] is None
    subject = a["subject"]
    assert subject == "pid:" + "ab" * 16  # the pid of the device
    assert out["receipt"]["subject"] == subject  # the node claimed the invite
    assert net.identity.is_member(subject)
    assert net.identity.email_of(subject) == "ada@lab.org"
    assert net.identity.orcid_of(subject) is None
    # The device binds seq 0 with this assertion, as for any sign-in.
    entry = make_binding(
        subject=subject, op="add", seq=0, prev=None, device=dev,
        created_at=net.identity.now_dt(), authority={"assertion": out["assertion"]},
        orcid_commitment=None, pop=sign_possession(subject, dev, key),
    )  # fmt: skip
    net.identity.submit(subject, entry)
    assert dev["ed25519"] in net.identity.active_devices(subject)
    me = net.identity.me(subject)
    assert me["findable"] and not me["orcid_linked"] and me["email"] == "ada@lab.org"
    auth = {"Authorization": "Bearer " + out["session"]["token"]}
    assert net.tc.get("/me", headers=auth).json()["invited_by"] == {"by": None, "via": "node"}


def test_invite_is_single_use_and_checked(net):
    token = _token(net)
    key, _ = _dev()
    assert _signin(net, token, key).status_code == 200
    again = _signin(net, token, _dev()[0])
    assert again.status_code == Conflict.status
    assert _signin(net, "00" * 32, key).status_code == NotFound.status
    assert _signin(net, "not hex", key).status_code == NotFound.status
    old = _token(net, days=1)
    net.clock.t += 2 * 86400
    assert _signin(net, old, key).status_code == Gone.status
    assert _signin(net, "lab:" + "0" * 32, key).status_code == NotFound.status


def test_stated_email_is_not_a_sign_in_address(net):
    key, _ = _dev()
    subject = _signin(net, _token(net), key, email="ada@lab.org").json()["session"]["subject"]
    # An email code for the stated address makes no session for the account.
    start = _post(net, "/auth/email/start", {
        "device_key": key.public_bytes().hex(), "email": "ada@lab.org",
        "nonce": secrets.token_hex(16), "purpose": "login",
    }).json()  # fmt: skip
    code = net.mailer.outbox[-1][2].split("code is ")[1][:8]
    r = _post(net, "/auth/email/verify", {"challenge_id": start["challenge_id"], "code": code})
    assert r.status_code == Forbidden.status
    # Another member finds the person by the stated address (findable by default).
    other = _signin(net, _token(net), _dev()[0]).json()["session"]["subject"]
    assert net.identity.people.resolve_email(other, "ADA@lab.org") == {"subject": subject}
    net.identity.people.set_findable(subject, False)
    with pytest.raises(NotFound):
        net.identity.people.resolve_email(other, "ada@lab.org")
    # A second person who states the same address does not get it.
    third = _signin(net, _token(net), _dev()[0], email="ada@lab.org").json()
    assert net.identity.email_of(third["session"]["subject"]) is None


def test_bad_email_is_refused(net):
    r = _signin(net, _token(net), _dev()[0], email="not an address")
    assert r.status_code == 400 and "email address" in r.json()["detail"]


def test_invite_chain(net):
    key, _ = _dev()
    first = _signin(net, _token(net), key).json()["session"]["subject"]
    net.identity.db.execute("UPDATE members SET role = 'organizer' WHERE subject = ?", (first,))
    second = _signin(net, _token(net, created_by=first), _dev()[0]).json()["session"]["subject"]
    assert net.admission.invited_by(second) == {"by": first, "via": "node"}
    chain = {row["subject"]: row for row in net.admission.invite_chain()}
    assert chain[second]["by"] == first and chain[second]["by_name"] == "A member"
    assert chain[first]["by"] is None and chain[first]["via"] == "node"


def test_reader_invite_keeps_the_contact_proof(net):
    readers = ReaderInvites(net.identity, AdmissionStore(net.identity.db, net.identity.lock))
    owner = _signin(net, _token(net), _dev()[0]).json()["session"]["subject"]
    made = readers.create(owner, {"kind": "email", "value": "reader@uni.edu"}, None)
    token = parse_invite_url(made["invite_url"])["token"]
    key, _ = _dev()
    out = _signin(net, token, key).json()
    assert out["needs"] == "email_code" and out["email_hint"] == "r…@uni.edu"
    assert "assertion" not in out
    code = net.mailer.outbox[-1][2].split("code is ")[1][:8]
    signed = _post(net, "/auth/email/verify", {"challenge_id": out["challenge_id"], "code": code})
    subject = signed.json()["session"]["subject"]
    token_s = signed.json()["session"]["token"]
    claim = _post(net, "/invites/claim", {"token": token}, token_s)
    assert claim.status_code == 200 and net.identity.is_member(subject)
    orcid = readers.create(owner, {"kind": "orcid", "value": "fake-reader"}, None)
    t2 = parse_invite_url(orcid["invite_url"])["token"]
    assert _signin(net, t2, _dev()[0]).json() == {"needs": "orcid"}


def test_link_orcid_after_join(net):
    key, _ = _dev()
    session = _signin(net, _token(net), key).json()["session"]
    subject, tok = session["subject"], session["token"]
    from anagram.identity.app.browsers import pkce

    verifier, challenge = pkce()
    body = {
        "code_challenge": challenge, "device_key": key.public_bytes().hex(),
        "login_hint": "fake-linked", "nonce": secrets.token_hex(16), "orcid_salt": "11" * 32,
        "purpose": "link",
        "return_to": "http://127.0.0.1:9/callback",
    }  # fmt: skip
    assert _post(net, "/auth/orcid/start", body).status_code == 401  # needs a session
    start = _post(net, "/auth/orcid/start", body, tok).json()
    back = net.browser().open(start["authorize_url"])
    out = _post(net, "/auth/orcid/exchange", {
        "code": back["code"], "code_verifier": verifier, "flow_id": start["flow_id"],
    }).json()  # fmt: skip
    assert out["linked"] and out["profile"]["orcid"] == "fake-linked"
    assert out["profile"]["orcid_salt"] == "11" * 32
    assert net.identity.orcid_of(subject) == "fake-linked"
    assert net.identity.me(subject)["orcid_linked"]
    # The key directory does not change (rule 6).
    assert net.identity.key_state(subject).orcid_commitment is None
    # A linked iD does not sign in: the device key and the kit do that.
    verifier, challenge = pkce()
    body.update(code_challenge=challenge, purpose="login", nonce=secrets.token_hex(16))
    del body["orcid_salt"]
    start = _post(net, "/auth/orcid/start", body).json()
    back = net.browser().open(start["authorize_url"])
    r = _post(net, "/auth/orcid/exchange", {
        "code": back["code"], "code_verifier": verifier, "flow_id": start["flow_id"],
    })  # fmt: skip
    assert r.status_code == 403 and "recovery kit" in r.json()["detail"]


def test_mask_email():
    assert mask_email("ada@lab.org") == "a…@lab.org"
