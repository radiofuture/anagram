"""Sign in again without an invite (purpose "login").

A member signs in again with ORCID or email only. The node gives a session
only to a member, and only for a device that is active or not bound yet.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from anagram.core.errors import ClientError
from anagram.core.nodeapi import NodeHTTPError
from anagram.identity.app.identity import login
from anagram.identity.app.session import read_session
from anagram.shell.client import Client

DAY = 86400


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def do_login(net, home, orcid, **kw):
    return login(
        home,
        transport=net.transport,
        browser=net.browser(),
        login_hint=orcid,
        clock=net.clock,
        **kw,
        open_home=Client.open,
    )


def _raw_login(net, orcid, device="11" * 32, purpose="login"):
    """The ORCID flow at the HTTP level with a purpose. Return the response."""
    verifier = "v" * 50
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    start = net.tc.post(
        "/auth/orcid/start",
        json={
            "code_challenge": challenge.rstrip(b"=").decode(),
            "device_key": device,
            "login_hint": orcid,
            "nonce": "22" * 16,
            "purpose": purpose,
            "return_to": "http://127.0.0.1:5555/cb",
        },
    )
    if start.status_code != 200:
        return start
    start = start.json()
    back = net.browser()
    back.return_to = "http://127.0.0.1:5555/cb"
    params = back.open(start["authorize_url"])
    return net.tc.post(
        "/auth/orcid/exchange",
        json={"code": params["code"], "code_verifier": verifier, "flow_id": start["flow_id"]},
    )


def test_member_signs_in_again_after_the_invite_expired(net, tmp_path):
    link = net.invite(days=7)
    home = tmp_path / "a"
    r = net.join(home, "fake-alice", invite=link)
    history = len(r.client.directory.lookup(net.sid("fake-alice")).history)
    net.clock.t += 8 * DAY  # the session (7 days) and the invite have expired
    with pytest.raises(NodeHTTPError) as e:
        r.client.account.whoami()
    assert e.value.status == 401
    with pytest.raises(ClientError, match="expired"):
        net.join(home, "fake-alice", invite=link)
    out = do_login(net, home, "fake-alice")
    assert out.status == "signed_in" and out.subject == net.sid("fake-alice")
    assert out.receipt is None and out.kit_text is None  # no invite, no new kit
    assert out.client.account.whoami()["subject"] == net.sid("fake-alice")
    assert (
        len(out.client.directory.lookup(net.sid("fake-alice")).history) == history
    )  # no new binding
    assert read_session(out.client.keystore)["token"] == out.client.device.http.token
    # The Client method does the same.
    net.clock.t += 8 * DAY
    out.client.sign_in(browser=net.browser(), login_hint="fake-alice")
    assert out.client.account.whoami()["subject"] == net.sid("fake-alice")


def test_member_signs_in_again_with_email(net, tmp_path):
    def code():
        return net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]

    r = net.join(tmp_path / "a", None, email="pi@example.org", email_code=code)
    net.clock.t += 8 * DAY
    out = login(
        tmp_path / "a",
        transport=net.transport,
        email="PI@example.org",
        email_code=code,
        clock=net.clock,
        open_home=Client.open,
    )
    assert out.status == "signed_in" and out.subject == r.subject


def test_non_member_cannot_sign_in_without_an_invite(net, tmp_path):
    home = tmp_path / "a"
    net.join(home, "fake-alice")
    # Another person signs in at the same home: the node refuses before the
    # client sees a session.
    with pytest.raises(NodeHTTPError) as e:
        do_login(net, home, "fake-stranger")
    assert e.value.status == 403
    r = _raw_login(net, "fake-stranger")
    assert r.status_code == 403 and "invite" in r.json()["detail"]
    assert net.identity.subject_for_orcid("fake-stranger") is None  # a login makes no account
    # Email: an unknown address is refused and gets no account.
    start = net.tc.post(
        "/auth/email/start",
        json={
            "device_key": "11" * 32,
            "email": "new@example.org",
            "nonce": "22" * 16,
            "purpose": "login",
        },
    ).json()
    code = net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]
    r = net.tc.post(
        "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": code}
    )
    assert r.status_code == 403
    assert net.identity._one("SELECT 1 FROM email_accounts WHERE email = 'new@example.org'") is None
    # The join purpose (with an invite claim after it) still works.
    assert _raw_login(net, "fake-stranger", purpose="join").status_code == 200
    assert _raw_login(net, "fake-stranger", purpose="other").status_code == 400


def test_removed_device_cannot_sign_in_again(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-two", invite=link).client
    r = net.join(tmp_path / "desktop", "fake-two", invite=link)
    first.account.add_device(r.device_request)
    second = net.join(tmp_path / "desktop", "fake-two", invite=link).client
    first.directory.bind(
        first.directory.lookup(first.device.subject),
        op="remove",
        device=second.device.my_device(),
        authority={"device": first.device.my_device()["ed25519"]},
        authority_key=first.device.device_key(),
    )
    with pytest.raises(NodeHTTPError) as e:
        do_login(net, tmp_path / "desktop", "fake-two")
    assert e.value.status == 403 and "removed" in e.value.detail
    # The active device still signs in.
    assert do_login(net, tmp_path / "laptop", "fake-two").status == "signed_in"


def test_new_device_sign_in_follows_the_binding_rules(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-pair", invite=link).client
    r = net.join(tmp_path / "desktop", "fake-pair", invite=link)
    assert r.status == "pending_device"
    assert net.join(tmp_path / "spare", "fake-pair", invite=link).status == "pending_device"
    net.clock.t += 8 * DAY  # the invite expires before the approval
    # Not approved yet: the login gives the device request again.
    out = do_login(net, tmp_path / "desktop", "fake-pair")
    assert out.status == "pending_device" and out.device_request
    first.sign_in(browser=net.browser(), login_hint="fake-pair")  # its session expired too
    first.account.add_device(out.device_request)
    out = do_login(net, tmp_path / "desktop", "fake-pair")
    assert out.status == "signed_in"
    assert set(first.directory.lookup(net.sid("fake-pair")).devices) == {
        first.device.my_device()["ed25519"],
        out.client.device.my_device()["ed25519"],
    }
    # A reset (all devices lost) with a login: a new kit, old sessions end.
    old = out.client.device.http.token
    out = do_login(net, tmp_path / "spare", "fake-pair", reset=True)
    assert out.status == "signed_in" and out.kit_text and out.recovery_code
    assert set(out.client.directory.lookup(net.sid("fake-pair")).devices) == {
        out.client.device.my_device()["ed25519"]
    }
    assert net.tc.get("/me", headers=auth(old)).status_code == 401


def test_login_checks_the_pinned_node_key(net, tmp_path):
    home = tmp_path / "a"
    net.join(home, "fake-alice")
    cfg = json.loads((home / "config.json").read_text())
    cfg["identity"]["node_key"] = "cd" * 32
    (home / "config.json").write_text(json.dumps(cfg))
    with pytest.raises(ClientError, match="not the node"):
        do_login(net, home, "fake-alice")
    with pytest.raises(ClientError, match="invite"):
        do_login(net, tmp_path / "empty", "fake-alice")


def test_recovered_keys_sign_in_without_an_invite(net, tmp_path):
    from anagram.identity.app.kit import recover

    r = net.join(tmp_path / "old", "fake-forgetful")
    kit = r.kit_text
    net.clock.t += 30 * DAY
    recover(tmp_path / "new", kit, transport=net.transport, clock=net.clock, open_home=Client.open)
    out = do_login(net, tmp_path / "new", "fake-forgetful")
    assert out.status == "signed_in" and out.client.account.whoami()["subject"] == net.sid(
        "fake-forgetful"
    )


def test_login_after_all_devices_were_removed_binds_with_a_reset(net, tmp_path):
    link = net.invite()
    laptop = net.join(tmp_path / "laptop", "fake-solo", invite=link).client
    assert net.join(tmp_path / "spare", "fake-solo", invite=link).status == "pending_device"
    laptop.directory.bind(  # the only device removes itself
        laptop.directory.lookup(laptop.device.subject),
        op="remove",
        device=laptop.device.my_device(),
        authority={"device": laptop.device.my_device()["ed25519"]},
        authority_key=laptop.device.device_key(),
    )
    out = do_login(net, tmp_path / "spare", "fake-solo")
    assert out.status == "signed_in" and out.recovery_code
    state = out.client.directory.lookup(net.sid("fake-solo"))
    assert state.history[-1]["op"] == "reset"
    assert set(state.devices) == {out.client.device.my_device()["ed25519"]}
