"""P2: identity and joining, end to end over FastAPI TestClient. No network."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import NODE_URL, make_net
from fastapi.testclient import TestClient
from softauthn import SoftAuthenticator

from anagram.admission.formats import parse_invite_url
from anagram.core.canonical import canonical_json
from anagram.core.crypto.signing import SigningKey
from anagram.core.errors import ClientError, LogMisbehaved, NodeError
from anagram.core.nodeapi import NodeHTTPError
from anagram.core.signed import b64url, unb64url
from anagram.identity.app.kit import parse_kit, recover
from anagram.identity.app.session import read_session
from anagram.identity.formats.backup import decode_secret, encode_secret
from anagram.identity.formats.documents import (
    PUBLIC_LOG_KINDS,
    device_json,
    make_assertion,
    make_binding,
    sign_possession,
)
from anagram.identity.node.orcid import OrcidOAuth
from anagram.network.groups.app.labroster import LabError
from anagram.proofs.log.store import SQLiteLog
from anagram.proofs.log.witness import Witness
from anagram.proofs.node.service import EntryRejected, NodeService, validate_entry
from anagram.shell.client import Client
from anagram.shell.node.app import create_app


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ invites


def test_fake_orcid_join_end_to_end(net, tmp_path):
    r = net.join(tmp_path / "a", "fake-chen-pi", "Mei Chen", institution="fake-northbridge")
    assert r.status == "joined" and r.subject == net.sid("fake-chen-pi")
    assert r.subject.startswith("pid:") and "fake-chen-pi" not in r.subject
    c = r.client
    me = c.account.whoami()
    assert me["role"] == "member" and me["devices"] == [c.device.my_device()["ed25519"]]
    assert me["identity"]["display_name"] == "Mei Chen"
    assert me["identity"]["institution"] == "fake-northbridge"
    assert r.kit_path is None and r.recovery_code in r.kit_text
    assert r.client.account.pending_kit().text == r.kit_text  # kept in the encrypted vault
    # Another member looks up the first one's keys, with log proofs.
    b = net.join(tmp_path / "b", "fake-okafor-pi").client
    keys = b.directory.lookup(net.sid("fake-chen-pi"))
    assert keys.devices == {c.device.my_device()["ed25519"]: c.device.my_device()}
    assert b.directory.monitor() == [] and c.directory.monitor() == []
    with pytest.raises(ClientError, match="no active keys"):
        b.directory.lookup("pid:" + "ab" * 16)


def test_invite_expiry(net, tmp_path):
    link = net.invite(days=1)
    net.clock.t += 2 * 86400
    with pytest.raises(ClientError, match="expired"):
        net.join(tmp_path / "a", "fake-late", invite=link)
    # The node also refuses (a client with a wrong clock cannot pass).
    net.clock.t -= 2 * 86400
    token = parse_invite_url(link)["token"]
    sess = _session(net, "fake-late")  # signed in, no claim yet
    net.clock.t += 2 * 86400
    r = net.tc.post("/invites/claim", json={"token": token}, headers=auth(sess))
    assert r.status_code == 410


def _session(net, orcid):
    """Sign in through the fake ORCID flow at the HTTP level; return the token."""
    import base64
    import hashlib

    verifier = "v" * 50
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    start = net.tc.post(
        "/auth/orcid/start",
        json={
            "code_challenge": challenge.rstrip(b"=").decode(),
            "device_key": "11" * 32,
            "login_hint": orcid,
            "nonce": "22" * 16,
            "return_to": "http://127.0.0.1:5555/cb",
        },
    ).json()
    back = net.browser()
    back.return_to = "http://127.0.0.1:5555/cb"
    params = back.open(start["authorize_url"])
    r = net.tc.post(
        "/auth/orcid/exchange",
        json={"code": params["code"], "code_verifier": verifier, "flow_id": start["flow_id"]},
    )
    assert r.status_code == 200, r.text
    return r.json()["session"]["token"]


def test_invite_single_use_and_idempotent_claim(net, tmp_path):
    link = net.invite()
    token = parse_invite_url(link)["token"]
    r1 = net.join(tmp_path / "a", "fake-one", invite=link)
    sess = r1.client.node.token
    again = net.tc.post("/invites/claim", json={"token": token}, headers=auth(sess)).json()
    assert again == r1.receipt  # same receipt
    other = _session(net, "fake-two")
    r = net.tc.post("/invites/claim", json={"token": token}, headers=auth(other))
    assert r.status_code == 409
    with pytest.raises(NodeHTTPError) as e:
        net.join(tmp_path / "b", "fake-two", invite=link)
    assert e.value.status == 409
    assert (
        net.tc.post("/invites/claim", json={"token": "00" * 32}, headers=auth(other)).status_code
        == 404
    )


def test_tampered_invite_rejected(net, tmp_path):
    link = net.invite()
    doc = parse_invite_url(link)
    doc["community"] = "A different community"
    bad = f"{NODE_URL}/join#{b64url(canonical_json(doc))}"
    with pytest.raises(ClientError, match="signature"):
        net.join(tmp_path / "a", "fake-x", invite=bad)


def test_wrong_pinned_fingerprint_rejected(net, tmp_path):
    doc = parse_invite_url(net.invite())
    doc["node_key"] = "ab" * 32  # an attacker's node, or a typo
    bad = f"{NODE_URL}/join#{b64url(canonical_json(doc))}"
    with pytest.raises(ClientError, match="not the node in the invite"):
        net.join(tmp_path / "a", "fake-x", invite=bad)
    assert not (tmp_path / "a").exists()


def test_organizer_creates_invites(tmp_path):
    net = make_net(tmp_path, organizers=["fake-organizer"])
    org = net.join(tmp_path / "o", "fake-organizer").client
    assert org.account.whoami()["role"] == "organizer"
    r = net.tc.post("/invites", json={"expires_days": 3}, headers=auth(org.node.token))
    assert r.status_code == 200
    m = net.join(tmp_path / "m", "fake-member", invite=r.json()["invite_url"]).client
    assert net.tc.post("/invites", json={}, headers=auth(m.node.token)).status_code == 403


# --------------------------------------------------------------- sign-in


def test_forged_assertion_rejected_by_client(net, tmp_path):
    attacker = SigningKey.generate()

    def evil(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if path == "/auth/orcid/exchange":
            a = out["assertion"]
            out["assertion"] = make_assertion(
                subject="pid:" + "ab" * 16,
                orcid_commitment=a["orcid_commitment"],
                method=a["method"],
                audience=bytes.fromhex(a["audience"]),
                nonce=a["nonce"],
                community=a["community"],
                node_key=a["node_key"],
                issued_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(days=1),
                key=attacker,
            )
        return out

    with pytest.raises(ClientError, match="not valid"):
        net.join(tmp_path / "a", "fake-x", transport=evil)


def test_forged_assertion_rejected_by_node(net, tmp_path):
    c = net.join(tmp_path / "a", "fake-mallory").client
    victim = "pid:" + "ab" * 16
    mallory = net.sid("fake-mallory")
    k = SigningKey.generate()
    dev = device_json(k.public_bytes(), b"\1" * 32)
    fake = make_assertion(
        subject=mallory,
        orcid_commitment=net.commitment("fake-mallory"),
        method="orcid-fake",
        audience=k.public_bytes(),
        nonce="00" * 16,
        community="Test community",
        node_key=c.config["identity"]["node_key"],
        issued_at=datetime.fromtimestamp(net.clock.t, UTC),
        expires_at=datetime.fromtimestamp(net.clock.t + 600, UTC),
        key=k,  # not the node key
    )
    for subj in (victim, mallory):
        entry = make_binding(
            subject=subj,
            op="add" if subj == victim else "reset",
            seq=0 if subj == victim else 1,
            prev=None if subj == victim else b"\0" * 32,
            device=dev,
            created_at=datetime.fromtimestamp(net.clock.t, UTC),
            authority={"assertion": fake},
            orcid_commitment=fake["orcid_commitment"],
            pop=sign_possession(subj, dev, k),
        )
        r = net.tc.post("/log/entries", json={"entry": entry}, headers=auth(c.node.token))
        assert r.status_code in (400, 403), r.text


def test_pkce_and_return_to(net):
    body = {
        "code_challenge": "x" * 43,
        "device_key": "11" * 32,
        "nonce": "22" * 16,
        "return_to": "https://evil.example/cb",
    }
    assert net.tc.post("/auth/orcid/start", json=body).status_code == 400
    body["return_to"] = "http://127.0.0.1:4444/cb"
    start = net.tc.post("/auth/orcid/start", json={**body, "login_hint": "fake-p"}).json()
    b = net.browser()
    b.return_to = body["return_to"]
    code = b.open(start["authorize_url"])["code"]
    r = net.tc.post(
        "/auth/orcid/exchange",
        json={"code": code, "code_verifier": "wrong", "flow_id": start["flow_id"]},
    )
    assert r.status_code == 401
    # The fake ORCID refuses a redirect URI that is not the node callback.
    r = net.tc.get(
        "/fake-orcid/authorize",
        params={"state": "s", "redirect_uri": "http://127.0.0.1:1/x", "orcid": "fake-p"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_real_orcid_adapter_requests():
    posted = {}

    def post(url, fields):
        posted.update(url=url, fields=fields)
        return {"orcid": "0000-0002-1825-0097", "name": "Josiah Carberry", "access_token": "t"}

    a = OrcidOAuth("APP-123", "secret", "sandbox", post=post)
    cb = "https://node.example.org/auth/orcid/callback"
    url = a.authorize_url("st", cb)
    assert url.startswith("https://sandbox.orcid.org/oauth/authorize?")
    assert "scope=%2Fauthenticate" in url and "redirect_uri=https%3A%2F%2Fnode.example.org" in url
    user = a.exchange("code1", cb)
    assert user.orcid == "0000-0002-1825-0097"
    assert posted["url"] == "https://sandbox.orcid.org/oauth/token"
    assert posted["fields"]["redirect_uri"] == cb
    assert posted["fields"]["grant_type"] == "authorization_code"


def test_email_sign_in(net, tmp_path):
    def code():
        return net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]

    r = net.join(tmp_path / "a", None, email="Student@Example.org", email_code=code)
    assert r.status == "joined" and r.subject.startswith("pid:")
    assert "student@example.org" not in json.dumps(r.client.directory.lookup(r.subject).history)
    # Attempt limit, then lockout.
    start = net.tc.post(
        "/auth/email/start",
        json={"device_key": "11" * 32, "email": "x@example.org", "nonce": "22" * 16},
    ).json()
    real = code()
    for _ in range(5):
        bad = net.tc.post(
            "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": "0"}
        )
        assert bad.status_code == 401
    ok = net.tc.post(
        "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": real}
    )
    assert ok.status_code == 401  # locked
    # Expiry.
    start = net.tc.post(
        "/auth/email/start",
        json={"device_key": "11" * 32, "email": "y@example.org", "nonce": "22" * 16},
    ).json()
    real = code()
    net.clock.t += 601
    r = net.tc.post(
        "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": real}
    )
    assert r.status_code == 401
    # Purpose binding: an email challenge is not a passkey challenge.
    r = net.tc.post(
        "/auth/passkeys/login/verify",
        json={"challenge_id": start["challenge_id"], "credential": {"id": "x"}},
    )
    assert r.status_code == 401
    # Rate limit per address.
    for _ in range(6):
        r = net.tc.post(
            "/auth/email/start",
            json={"device_key": "11" * 32, "email": "z@example.org", "nonce": "22" * 16},
        )
    assert r.status_code == 429


def test_passkey_register_and_login(net, tmp_path):
    c = net.join(tmp_path / "a", "fake-passkey").client
    tok = c.node.token
    authn = SoftAuthenticator("node.test", NODE_URL)
    opts = net.tc.post("/auth/passkeys/register/options", headers=auth(tok)).json()
    assert opts["options"]["rp"]["id"] == "node.test"
    cred = authn.register(opts["options"])
    r = net.tc.post(
        "/auth/passkeys/register/verify",
        json={"challenge_id": opts["challenge_id"], "credential": cred},
        headers=auth(tok),
    )
    assert r.status_code == 200, r.text
    # Wrong origin is refused.
    opts2 = net.tc.post("/auth/passkeys/register/options", headers=auth(tok)).json()
    other = SoftAuthenticator("node.test", NODE_URL)
    bad = other.register(opts2["options"], origin="https://evil.example")
    r = net.tc.post(
        "/auth/passkeys/register/verify",
        json={"challenge_id": opts2["challenge_id"], "credential": bad},
        headers=auth(tok),
    )
    assert r.status_code == 401
    # Log in with the passkey: a new session.
    lo = net.tc.post("/auth/passkeys/login/options", json={"subject": c.device.subject}).json()
    assert lo["options"]["allowCredentials"][0]["id"] == cred["id"]
    r = net.tc.post(
        "/auth/passkeys/login/verify",
        json={"challenge_id": lo["challenge_id"], "credential": authn.login(lo["options"])},
    )
    assert r.status_code == 200, r.text
    new = r.json()["session"]["token"]
    assert net.tc.get("/me", headers=auth(new)).json()["subject"] == c.device.subject
    # The challenge is single use.
    r = net.tc.post(
        "/auth/passkeys/login/verify",
        json={"challenge_id": lo["challenge_id"], "credential": authn.login(lo["options"])},
    )
    assert r.status_code == 401


# ------------------------------------------------------- log submissions


def test_unauthenticated_and_non_member_submission(net, tmp_path):
    entry = {"commitment": "00" * 32, "kind": "finding", "schema": "anagram.log_entry.v1"}
    assert net.tc.post("/log/entries", json={"entry": entry}).status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert net.tc.post("/log/entries", json={"entry": entry}, headers=bad).status_code == 401
    outsider = _session(net, "fake-outsider")  # signed in, never claimed an invite
    r = net.tc.post("/log/entries", json={"entry": entry}, headers=auth(outsider))
    assert r.status_code == 403
    # Public reads stay public.
    assert net.tc.get("/log/checkpoint").status_code == 200
    assert net.tc.get("/node/trust").status_code == 200


def test_submission_rate_limit(tmp_path):
    net = make_net(tmp_path, submit_per_minute=3)
    c = net.join(tmp_path / "a", "fake-busy").client  # the key binding uses 1
    entry = {"commitment": "00" * 32, "kind": "finding", "schema": "anagram.log_entry.v1"}
    codes = [
        net.tc.post("/log/entries", json={"entry": entry}, headers=auth(c.node.token)).status_code
        for _ in range(3)
    ]
    assert codes == [200, 200, 429]
    net.clock.t += 61
    r = net.tc.post("/log/entries", json={"entry": entry}, headers=auth(c.node.token))
    assert r.status_code == 200


def test_member_commits_finding(net, tmp_path):
    c = net.join(tmp_path / "a", "fake-committer").client
    f = tmp_path / "x.txt"
    f.write_text("data")
    bundle = c.findings.commit_finding([f], claim="c")
    assert bundle.log.tree_size == 2


# ---------------------------------------------------------- malicious node


def test_directory_entry_not_in_log_detected(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    b = net.join(tmp_path / "b", "fake-bob").client
    alice = a.device.subject
    k = SigningKey.generate()
    swapped = device_json(k.public_bytes(), b"\2" * 32)

    def evil(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if path == f"/directory/{alice}":
            e = copy.deepcopy(out["entries"][0])
            e["entry"]["device"] = swapped  # a key the node made up
            out["entries"] = [e]
        return out

    b.node.transport = evil
    with pytest.raises(LogMisbehaved, match="not in the log"):
        b.directory.lookup(net.sid("fake-alice"))
    del a


def test_directory_answer_that_hides_a_reset_is_refused(net, tmp_path):
    """Security review 2, fix 1: a lookup must not accept a stale chain. The
    node drops the reset of a stolen device from the directory answer."""
    chen = net.join(tmp_path / "chen", "fake-chen").client
    old = net.join(tmp_path / "ok1", "fake-okafor").client
    old_key = old.device.my_device()["ed25519"]
    new = net.join(tmp_path / "ok2", "fake-okafor", reset=True).client
    assert set(chen.directory.lookup(net.sid("fake-okafor")).devices) == {
        new.device.my_device()["ed25519"]
    }
    okafor = net.sid("fake-okafor")

    def evil(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if method == "GET" and path.startswith(f"/directory/{okafor}"):
            out["entries"] = out["entries"][:1]
        return out

    chen.device.http.transport = evil
    with pytest.raises(LogMisbehaved, match="omits"):
        chen.directory.lookup(net.sid("fake-okafor"))
    # A client that did not see the log before also refuses.
    fresh = net.join(tmp_path / "fresh", "fake-fresh").client
    fresh.device.http.transport = evil
    with pytest.raises(LogMisbehaved, match="omits"):
        fresh.directory.lookup(net.sid("fake-okafor"))
    assert old_key not in net.identity.key_state(okafor).devices


def test_reset_revokes_sessions_of_old_devices(net, tmp_path):
    """Security review 2, fix 3: after a reset, the session of a stolen device
    cannot read the guardian set or delete backups."""
    net.join(tmp_path / "a", "fake-alice")
    net.join(tmp_path / "b", "fake-bob")
    stolen = net.join(tmp_path / "ok1", "fake-okafor").client
    stolen.guardians.guardians_set([net.sid("fake-alice"), net.sid("fake-bob")], 2)
    old_token = stolen.device.http.token
    net.clock.t += 3600
    new = net.join(tmp_path / "ok2", "fake-okafor", reset=True).client
    new.guardians.guardians_set([net.sid("fake-alice"), net.sid("fake-bob")], 2)
    out = new.device.http.call("GET", "/guardians", auth=True)
    for method, path in (
        ("GET", "/guardians"),
        ("DELETE", f"/recovery/backup/{out['backup_id']}"),
        ("GET", "/me"),
    ):
        r = net.tc.request(method, path, headers=auth(old_token))
        assert r.status_code == 401, (method, path)
    assert net.transport("GET", f"/recovery/backup/{out['backup_id']}", None)
    assert new.account.whoami()["devices"] == [new.device.my_device()["ed25519"]]


def test_session_of_removed_device_is_refused(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-two", invite=link).client
    r = net.join(tmp_path / "desktop", "fake-two", invite=link)
    first.account.add_device(r.device_request)
    second = net.join(tmp_path / "desktop", "fake-two", invite=link).client
    token = second.device.http.token
    assert net.tc.get("/me", headers=auth(token)).status_code == 200
    first.directory.bind(
        first.directory.lookup(first.device.subject),
        op="remove",
        device=second.device.my_device(),
        authority={"device": first.device.my_device()["ed25519"]},
        authority_key=first.device.device_key(),
    )
    assert net.tc.get("/me", headers=auth(token)).status_code == 401
    assert first.account.whoami()["devices"] == [first.device.my_device()["ed25519"]]


def test_logout_ends_the_session(net, tmp_path):
    c = net.join(tmp_path / "a", "fake-alice").client
    token = c.device.http.token
    c.account.logout()
    assert net.tc.get("/me", headers=auth(token)).status_code == 401
    assert read_session(c.keystore) is None
    with pytest.raises(NodeHTTPError):
        c.account.whoami()


def test_log_fork_detected(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    b = net.join(tmp_path / "b", "fake-bob").client
    assert b.directory.lookup(net.sid("fake-alice")).devices
    # The operator makes a second log (and resets its own witness) in which
    # Alice has a key that the operator holds.
    nh = net.home
    forked = NodeService(
        SQLiteLog(tmp_path / "fork.sqlite"),
        nh.log_signer(),
        [Witness(nh.witness_signer(), tmp_path / "fork-w.sqlite", [nh.log_signer().verifier])],
        nh.anchors(),
        public_kinds=PUBLIC_LOG_KINDS,
    )
    k = SigningKey.generate()
    dev = device_json(k.public_bytes(), b"\3" * 32)
    now = datetime.fromtimestamp(net.clock.t, UTC)
    alice = net.sid("fake-alice")
    assertion = make_assertion(
        subject=alice,
        orcid_commitment=net.commitment("fake-alice"),
        method="orcid-fake",
        audience=k.public_bytes(),
        nonce="00" * 16,
        community="Test community",
        node_key=nh.fingerprint(),
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        key=nh.assertion_key(),
    )
    entry = make_binding(
        subject=alice,
        op="add",
        seq=0,
        prev=None,
        device=dev,
        created_at=now,
        authority={"assertion": assertion},
        orcid_commitment=assertion["orcid_commitment"],
        pop=sign_possession(alice, dev, k),
    )
    for _ in range(3):
        forked.submit(
            {"commitment": "aa" * 32, "kind": "finding", "schema": "anagram.log_entry.v1"}
        )
    forked.submit(entry)
    net.identity.log = forked
    net.identity.db.execute("DELETE FROM directory")
    net.identity.db.execute(
        "INSERT INTO directory VALUES (3, ?, 0, ?)",
        (alice, canonical_json(entry).decode()),
    )
    fork_tc = TestClient(
        create_app(forked, nh.trust_info(), net.identity, admission=net.admission),
        base_url=NODE_URL,
    )

    def fork_transport(method, path, body, headers=None):
        r = fork_tc.request(method, path, json=body, headers=headers or {})
        if r.status_code >= 400:
            raise NodeHTTPError(r.status_code, r.json().get("detail", ""))
        return r.json()

    b.node.transport = fork_transport
    # The fork has a valid signature and witness cosignature (the operator runs
    # the witness here), but it does not extend the log that Bob saw.
    with pytest.raises(LogMisbehaved, match="consistent"):
        b.directory.lookup(net.sid("fake-alice"))
    del a


def test_node_key_swap_detected_by_owner_monitor(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    assert a.directory.monitor() == []
    # The node signs its own assertion and resets Alice to a key it holds. The
    # entry is valid and in the log, so others see it; Alice's monitor flags it.
    nh = net.home
    k = SigningKey.generate()
    dev = device_json(k.public_bytes(), b"\4" * 32)
    now = datetime.fromtimestamp(net.clock.t, UTC)
    alice = a.device.subject
    assertion = make_assertion(
        subject=alice,
        orcid_commitment=net.commitment("fake-alice"),
        method="orcid-fake",
        audience=k.public_bytes(),
        nonce="00" * 16,
        community="Test community",
        node_key=nh.fingerprint(),
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
        key=nh.assertion_key(),
    )
    state = net.identity.key_state(alice)
    entry = make_binding(
        subject=alice,
        op="reset",
        seq=state.seq + 1,
        prev=state.head,
        device=dev,
        created_at=now,
        authority={"assertion": assertion},
        orcid_commitment=assertion["orcid_commitment"],
        pop=sign_possession(alice, dev, k),
    )
    net.identity.submit(alice, entry)
    alerts = a.directory.monitor()
    assert any("unknown device key" in x for x in alerts)
    assert any("this device was removed" in x for x in alerts)
    assert a.vault.alerts() == alerts


def test_monitor_detects_changed_entries(net, tmp_path):
    a = net.join(tmp_path / "a", "fake-alice").client
    bob = net.join(tmp_path / "b", "fake-bob").subject

    def evil(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if path.startswith("/log/entries?"):
            out["entries"] = [e.replace(bob[-6:], "beef00") for e in out["entries"]]
        return out

    a.node.transport = evil
    with pytest.raises(LogMisbehaved, match="do not match"):
        a.directory.monitor()


# ---------------------------------------------------------- second device


def test_second_device_add(net, tmp_path):
    link = net.invite()
    first = net.join(tmp_path / "laptop", "fake-two-devices", invite=link).client
    r = net.join(tmp_path / "desktop", "fake-two-devices", invite=link)
    assert r.status == "pending_device" and r.device_request
    second = r.client
    first.account.add_device(r.device_request)
    r2 = net.join(tmp_path / "desktop", "fake-two-devices", invite=link)
    assert r2.status == "joined"
    keys = first.directory.lookup(net.sid("fake-two-devices"))
    assert set(keys.devices) == {
        first.device.my_device()["ed25519"],
        second.device.my_device()["ed25519"],
    }
    assert first.directory.monitor() == [] and second.directory.monitor() == []
    # A request from another person cannot be approved.
    other = net.join(tmp_path / "x", "fake-other").client
    with pytest.raises(ClientError):
        first.account.add_device(other.account.device_request())
    # Damaged requests fail.
    raw = json.loads(unb64url(r.device_request))
    raw["device"]["x25519"] = "55" * 32
    with pytest.raises(ClientError):
        first.account.add_device(b64url(canonical_json(raw)))


# ------------------------------------------------------------- recovery


def test_recovery_kit_restore(net, tmp_path):
    r = net.join(tmp_path / "old", "fake-forgetful")
    old = r.client
    kit = r.kit_text
    assert parse_kit(kit)["subject"] == old.device.subject
    new = recover(
        tmp_path / "new", kit, transport=net.transport, clock=net.clock, open_home=Client.open
    )
    assert new.device.device_key().seed() == old.device.device_key().seed()
    assert new.device.x25519_key().private_bytes() == old.device.x25519_key().private_bytes()
    assert (
        new.directory.lookup(net.sid("fake-forgetful")).devices
        == old.directory.lookup(net.sid("fake-forgetful")).devices
    )


def test_wrong_kit_fails(net, tmp_path):
    r = net.join(tmp_path / "old", "fake-forgetful")
    kit = r.kit_text
    secret = decode_secret(r.recovery_code)
    wrong = kit.replace(r.recovery_code, encode_secret(bytes([secret[0] ^ 1]) + secret[1:]))
    with pytest.raises(ClientError, match="no backup"):
        recover(tmp_path / "new", wrong, transport=net.transport, open_home=Client.open)
    with pytest.raises(ClientError, match="not an Anagram recovery kit"):
        recover(tmp_path / "new2", "hello", transport=net.transport, open_home=Client.open)
    other_node = kit.replace(parse_kit(kit)["node key"], "cd" * 32)
    with pytest.raises(ClientError, match="not the node"):
        recover(tmp_path / "new3", other_node, transport=net.transport, open_home=Client.open)


def test_node_never_stores_private_keys(net, tmp_path):
    link = net.invite()
    a = net.join(tmp_path / "a", "fake-secretive", invite=link)
    b = net.join(tmp_path / "b", "fake-secretive", invite=link)
    a.client.account.add_device(b.device_request)
    b = net.join(tmp_path / "b", "fake-secretive", invite=link)
    secrets_ = []
    for r in (a, b):
        c = r.client
        for raw in (
            c.device.device_key().seed(),
            c.device.x25519_key().private_bytes(),
            c.keystore.get("vault-key"),
            decode_secret(r.recovery_code),
        ):
            secrets_ += [raw, raw.hex().encode(), b64url(raw).encode()]
        secrets_.append(r.recovery_code.encode())
        secrets_.append(c.node.token.encode())  # sessions: stored only as hashes
    for path in net.home.dir.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            for s in secrets_:
                assert s not in data, f"{path} holds a client secret"


# ------------------------------------------------------- labs, identity


def test_labs(net, tmp_path):
    pi = net.join(tmp_path / "pi", "fake-chen-pi").client
    pd = net.join(tmp_path / "pd", "fake-chen-postdoc").client
    lab = pi.labs.lab_create("Chen Lab")
    lab = pi.labs.lab_add(lab["lab_id"], net.sid("fake-chen-postdoc"))
    assert lab["pi"] == pi.device.subject and pd.device.subject in lab["members"]
    # The roster rules refuse these on the client before a request.
    with pytest.raises(LabError):
        pd.labs.lab_add(lab["lab_id"], net.sid("fake-chen-pi"))
    with pytest.raises(NodeHTTPError) as e:  # not a member of this node
        pi.labs.lab_add(lab["lab_id"], "pid:" + "0f" * 16)
    assert e.value.status == 404
    pd.account.set_identity("Postdoc", institution="fake-northbridge", lab_id=lab["lab_id"])
    rec = net.tc.get(f"/identity/{pd.device.subject}", headers=auth(pi.node.token)).json()
    assert rec["lab_id"] == lab["lab_id"]
    assert pd.account.whoami()["labs"] == [lab["lab_id"]]
    other = net.join(tmp_path / "o", "fake-outside").client
    with pytest.raises(NodeHTTPError) as e:
        other.account.set_identity("X", lab_id=lab["lab_id"])
    assert e.value.status == 403
    assert net.tc.get(f"/identity/{pi.device.subject}").status_code == 401


def test_log_service_takes_only_the_public_kinds_it_is_given():
    """The log service knows no public entry kind by itself (layers plan X5):
    the node gives the L1 key binding check."""
    entry = {"kind": "key_binding", "schema": "anagram.key_binding.v1"}
    with pytest.raises(EntryRejected, match="exactly"):
        validate_entry(entry)
    with pytest.raises(EntryRejected, match="bad key binding"):
        validate_entry(entry, PUBLIC_LOG_KINDS)


def test_smtp_starttls_uses_ssl_context_and_rejects_multi_recipient(monkeypatch):
    import smtplib
    import ssl

    from anagram.identity.node.mailer import SMTPMailer

    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=30):
            calls["init"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, *, context=None):
            calls["context"] = context

        def login(self, user, password):
            calls["login"] = (user, password)

        def send_message(self, msg, from_addr=None, to_addrs=None):
            calls["send"] = (from_addr, to_addrs)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    mailer = SMTPMailer("mail.example.org", 587, "noreply@example.org", "u", "p")
    mailer.send("alice@example.org", "Code", "12345678")
    assert isinstance(calls["context"], ssl.SSLContext)
    assert calls["send"] == ("noreply@example.org", ["alice@example.org"])
    for bad in (
        "a@b.org,evil@c.org",
        "a@b.org;evil@c.org",
        "<a@b.org>",
        "a@b@c.org",
        "a@b.org\nBcc:x@y.org",
        '"a"@b.org',
    ):
        with pytest.raises(NodeError):
            mailer.send(bad, "Code", "body")
    with pytest.raises(ValueError, match="newlines"):
        mailer.send("alice@example.org", "Hi\r\nBcc: evil@c.org", "body")


def test_email_injection_rejected_and_key_state_is_read_only(net):
    from anagram.admission.node.reader import normalize_contact
    from anagram.identity.node.vouch import stated_email

    for bad in (
        "a@b.org,evil@c.org",
        "a@b.org;evil@c.org",
        "<a@b.org>",
        "a@b@c.org",
        "a@b.org\n",
        "user@localhost",
    ):
        with pytest.raises(NodeError):
            net.identity.email_signin.start(bad, "11" * 32, "22" * 16)
        with pytest.raises(NodeError):
            stated_email(bad)
        with pytest.raises(NodeError):
            normalize_contact({"kind": "email", "value": bad})

    # H16: key_state() must not mutate _dir.
    unknown = "pid:" + "ff" * 16
    assert net.identity.keys_of(unknown) is None
    st = net.identity.key_state(unknown)
    assert st.subject == unknown and not st.devices
    assert net.identity.keys_of(unknown) is None


def test_orcid_callback_releases_lock_and_caps_attempts(net):
    import threading

    from anagram.identity.app.browsers import pkce
    from anagram.identity.node.challenges import MAX_ATTEMPTS
    from anagram.identity.node.orcid import OrcidError, OrcidUser
    from anagram.identity.node.orcid_signin import FlowStart

    lock_was_free = False
    orig_exchange = net.identity.orcid_signin.orcid.exchange

    def checking_exchange(code, callback_url):
        nonlocal lock_was_free
        acquired = []

        def probe():
            got = net.identity.lock.acquire(blocking=False)
            if got:
                net.identity.lock.release()
            acquired.append(got)

        t = threading.Thread(target=probe)
        t.start()
        t.join()
        lock_was_free = acquired == [True]
        return orig_exchange(code, callback_url)

    net.identity.orcid_signin.orcid.exchange = checking_exchange
    _, challenge = pkce()
    browser = net.browser()
    started = net.identity.orcid_signin.start(
        FlowStart(
            device_key="11" * 32,
            nonce="22" * 16,
            code_challenge=challenge,
            return_to=browser.return_to,
            login_hint="fake-lock-check",
        )
    )
    back = browser.open(started["authorize_url"])
    assert back["code"] and lock_was_free

    # Failed callbacks are capped at MAX_ATTEMPTS.
    _, ch2 = pkce()
    s2 = net.identity.orcid_signin.start(
        FlowStart(
            device_key="11" * 32,
            nonce="33" * 16,
            code_challenge=ch2,
            return_to="http://127.0.0.1:9/cb",
        )
    )

    def fail_exchange(code, callback_url):
        if code == "bad":
            raise OrcidError("bad code")
        return OrcidUser("fake-ok", "Ok")

    net.identity.orcid_signin.orcid.exchange = fail_exchange
    for _ in range(MAX_ATTEMPTS):
        with pytest.raises(Exception, match="bad code"):
            net.identity.orcid_signin.callback(s2["flow_id"], "bad")
    with pytest.raises(NodeError, match="unknown, used, or expired"):
        net.identity.orcid_signin.callback(s2["flow_id"], "good")


def test_backups_enforce_size_and_count_caps(net, tmp_path):
    import base64

    from anagram.identity.formats.backup import MAX_BACKUP_BYTES, seal_backup
    from anagram.identity.node.backups import MAX_BACKUPS_PER_SUBJECT

    c = net.join_invite(tmp_path / "m").client
    sub = c.device.subject
    keys = {
        "device-ed25519": b"\x01" * 32,
        "device-x25519": b"\x02" * 32,
        "index-key": b"\x03" * 32,
        "vault-key": b"\x04" * 32,
    }
    big = seal_backup(b"\x01" * 20, sub, keys)
    big["ciphertext"] = base64.b64encode(b"x" * (MAX_BACKUP_BYTES + 1)).decode("ascii")
    with pytest.raises(NodeError, match="too large"):
        net.identity.backups.put(sub, big)
    # Existing backup from join_invite counts as 1; fill up to MAX_BACKUPS_PER_SUBJECT.
    existing = net.identity.db.execute(
        "SELECT COUNT(*) FROM backups WHERE subject = ?", (sub,)
    ).fetchone()[0]
    for i in range(MAX_BACKUPS_PER_SUBJECT - existing):
        doc = seal_backup(i.to_bytes(20, "big"), sub, keys)
        net.identity.backups.put(sub, doc)
    extra = seal_backup(b"\xff" * 20, sub, keys)
    with pytest.raises(NodeError, match="too many"):
        net.identity.backups.put(sub, extra)
