"""Recovery guardians (Shamir 2 of 3) end to end. No network."""

from __future__ import annotations

import pytest

from anagram.admission.app.join import node_of
from anagram.core.crypto import shamir
from anagram.core.errors import ClientError
from anagram.identity.app import guardians as g
from anagram.shell.client import Client


@pytest.fixture
def world(net, tmp_path, monkeypatch):
    people = {
        name: net.join(tmp_path / name, f"fake-{name}", name.title()).client
        for name in ("chen", "okafor", "varga", "helix")
    }
    seen: dict = {}
    real_split = shamir.split

    def spy(secret, k, n):
        seen["secret"] = secret
        seen["shares"] = real_split(secret, k, n)
        return seen["shares"]

    monkeypatch.setattr(g.shamir, "split", spy)
    out = people["chen"].guardians.guardians_set(
        [net.sid("fake-okafor"), net.sid("fake-varga"), net.sid("fake-helix")], threshold=2
    )
    assert out["threshold"] == 2 and len(out["guardians"]) == 3
    return people, seen


def start(net, home):
    return g.start_guardian_recovery(
        home,
        **node_of(net.invite()),
        transport=net.transport,
        browser=net.browser(),
        login_hint="fake-chen",
        clock=net.clock,
    )


def finish(net, home):
    return g.finish_guardian_recovery(
        home, transport=net.transport, clock=net.clock, open_home=Client.open
    )


def test_two_of_three_recover(net, world, tmp_path):
    people, _ = world
    chen = people["chen"]
    home = tmp_path / "chen-new"
    rid = start(net, home)
    with pytest.raises(ClientError, match="0 of 2"):
        finish(net, home)
    reqs = people["okafor"].guardians.guardian_requests()
    assert [r["request_id"] for r in reqs] == [rid] and reqs[0]["check"] == "ok"
    assert people["okafor"].guardians.guardian_approve(rid)["subject"] == net.sid("fake-chen")
    with pytest.raises(ClientError, match="1 of 2"):  # one guardian is not enough
        finish(net, home)
    people["helix"].guardians.guardian_approve(rid)
    restored = finish(net, home)
    assert restored.device.subject == net.sid("fake-chen")
    assert restored.device.my_device() == chen.device.my_device()
    assert restored.keystore.get("vault-key") == chen.keystore.get("vault-key")
    assert restored.account.whoami()["subject"] == net.sid("fake-chen")
    assert not (home / g.PENDING_DIR).exists()
    # A non-guardian sees no request and cannot approve.
    assert people["chen"].guardians.guardian_requests() == []
    with pytest.raises(ClientError, match="no recovery request"):
        people["chen"].guardians.guardian_approve(rid)


def test_one_of_three_fails(net, world, tmp_path):
    people, _ = world
    home = tmp_path / "chen-new"
    rid = start(net, home)
    people["varga"].guardians.guardian_approve(rid)
    people["varga"].guardians.guardian_approve(rid)  # the same guardian twice is still one share
    with pytest.raises(ClientError, match="1 of 2"):
        finish(net, home)


def test_share_ciphertexts_on_node_reveal_nothing(net, world, tmp_path):
    people, seen = world
    rid = start(net, tmp_path / "chen-new")
    people["okafor"].guardians.guardian_approve(rid)
    data = b"".join(p.read_bytes() for p in net.home.dir.rglob("*") if p.is_file())
    secret = seen["secret"]
    assert secret not in data and secret.hex().encode() not in data
    for _, share in seen["shares"]:
        assert share not in data and share.hex().encode() not in data
        assert share[:16] not in data and share[16:] not in data
    chen = people["chen"]
    for key in ("device-ed25519", "device-x25519", "vault-key"):
        raw = chen.keystore.get(key)
        assert raw not in data and raw.hex().encode() not in data


def test_forged_approval_is_ignored(net, world, tmp_path):
    """A node (or anyone) that adds a fake approval cannot give a wrong secret."""
    people, _ = world
    home = tmp_path / "chen-new"
    rid = start(net, home)
    people["okafor"].guardians.guardian_approve(rid)
    import base64
    import json

    fake = {
        "ciphertext": base64.b64encode(b"\x00" * 80).decode(),
        "guardian": net.sid("fake-varga"),
        "index": 2,
        "request_id": rid,
        "schema": "anagram.guardian_approval.v1",
    }
    net.vault._db.execute(
        "INSERT INTO approvals (request_id, idx, guardian, doc) VALUES (?, ?, ?, ?)",
        (rid, 2, net.sid("fake-varga"), json.dumps(fake)),
    )
    with pytest.raises(ClientError, match="do not give the secret"):
        finish(net, home)
    people["helix"].guardians.guardian_approve(rid)
    assert finish(net, home).device.subject == net.sid("fake-chen")


def test_new_guardian_set_retires_old_backup(net, world):
    people, _ = world
    chen = people["chen"]
    old = net.transport(
        "GET", "/guardians", None, {"Authorization": f"Bearer {chen.device.http.token}"}
    )
    chen.guardians.guardians_set([net.sid("fake-okafor"), net.sid("fake-varga")], threshold=2)
    with pytest.raises(Exception, match="404"):
        net.transport("GET", f"/recovery/backup/{old['backup_id']}", None)
    shares = people["helix"].device.http.call("GET", "/guardians/shares", auth=True)["shares"]
    assert shares == []
    with pytest.raises(ClientError):
        chen.guardians.guardians_set([net.sid("fake-okafor")], threshold=2)
    with pytest.raises(ClientError):
        chen.guardians.guardians_set([net.sid("fake-okafor"), net.sid("fake-chen")], threshold=2)


def test_request_needs_matching_session_and_slot(net, world, tmp_path):
    people, _ = world
    rid = start(net, tmp_path / "chen-new")
    approval = {
        "ciphertext": "AA==",
        "guardian": net.sid("fake-okafor"),
        "index": 3,
        "request_id": rid,
        "schema": "anagram.guardian_approval.v1",
    }
    path = f"/recovery/requests/{rid}/approvals"
    # A guardian can fill only its own slot.
    with pytest.raises(Exception, match="403"):
        people["okafor"].device.http.call("POST", path, {"approval": approval}, auth=True)
    # A person who is not a guardian sees no request.
    with pytest.raises(Exception, match="404"):
        people["chen"].device.http.call(
            "POST", path, {"approval": {**approval, "guardian": net.sid("fake-chen")}}, auth=True
        )
    # A request needs a session of the same person as the assertion.
    req = people["okafor"].device.http.call("GET", "/recovery/requests", auth=True)["requests"][0]
    with pytest.raises(Exception, match="403"):
        people["okafor"].device.http.call(
            "POST", "/recovery/requests", {"request": req["request"]}, auth=True
        )


def test_recovery_requests_expire(net, world, tmp_path):
    """Security review 2, fix 5: an old request cannot collect approvals."""
    people, _ = world
    okafor = people["okafor"]
    rid = start(net, tmp_path / "chen-new")
    (item,) = okafor.guardians.guardian_requests()
    assert item["check"] == "ok"
    # Sessions last 7 days too. Keep them open for this test.
    net.identity.db.execute("UPDATE sessions SET expires_at = expires_at + 30 * 86400")
    net.clock.t += 6 * 86400  # still young enough
    assert [r["request_id"] for r in okafor.guardians.guardian_requests()] == [rid]
    net.clock.t += 2 * 86400  # now older than 7 days
    # The node no longer serves it, and drops it with its approvals.
    assert okafor.guardians.guardian_requests() == []
    with pytest.raises(ClientError, match="no recovery request"):
        okafor.guardians.guardian_approve(rid)
    with pytest.raises(ClientError):
        finish(net, tmp_path / "chen-new")
    assert net.vault._db.execute("SELECT COUNT(*) FROM recovery_requests").fetchone()[0] == 0
    # A guardian also refuses an old request when a node still shows it.
    with pytest.raises(ClientError, match="too old"):
        okafor.guardians._check_request(rid, item["request"])


def test_finish_recovery_handles_duplicate_indices_and_missing_xkey(net, world, tmp_path):
    from anagram.identity.app.keychain import open_keystore

    people, _ = world
    new_home = tmp_path / "chen-dup"
    rid = start(net, new_home)
    people["okafor"].guardians.guardian_approve(rid)
    # Duplicate okafor's approval in the node response -> must raise ClientError, not ValueError.
    orig = net.transport

    def dup_transport(method, path, body=None, headers=None):
        res = orig(method, path, body, headers)
        if method == "GET" and path == f"/recovery/requests/{rid}":
            res = {**res, "approvals": [res["approvals"][0], res["approvals"][0]]}
        return res

    net.transport = dup_transport
    try:
        with pytest.raises(ClientError, match="valid shares"):
            finish(net, new_home)
    finally:
        net.transport = orig

    # Missing temp-x25519 must raise ClientError cleanly.
    people["varga"].guardians.guardian_approve(rid)
    ks = open_keystore(new_home / "guardian-recovery")
    ks.delete("temp-x25519")
    with pytest.raises(ClientError, match="temporary key"):
        finish(net, new_home)
