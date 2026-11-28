"""v2 fix 2: member ORCID iDs are not public.

The public log and the public directory show a person ID (`pid:`) and a salted
ORCID commitment. The node keeps the ORCID -> pid map private. A member finds
a pid by ORCID iD only if that person turned on "findable by ORCID". No network.
"""

from __future__ import annotations

import json

import pytest
from conftest import make_net
from test_ui_api import ORIGIN, join_via_ui, launched, ui_client

from anagram.core.errors import ClientError
from anagram.identity.app.browsers import pkce
from anagram.identity.formats.documents import check_orcid_opening, is_subject, new_pid
from anagram.identity.node.people import RESOLVES_PER_HOUR

pytestmark = pytest.mark.usefixtures("no_network")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def log_text(net) -> str:
    size = net.service.checkpoint()["tree_size"]
    return "\n".join(net.service.entries(0, size))


def test_log_and_directory_show_no_orcid_or_name(net, tmp_path):
    r = net.join(tmp_path / "a", "fake-chen-secret", "Mei Secret-Chen")
    c = r.client
    assert is_subject(c.device.subject)
    text = log_text(net)
    assert "fake-chen-secret" not in text and "Secret-Chen" not in text
    assert c.device.subject in text
    d = net.tc.get(f"/directory/{c.device.subject}").json()  # public, no session
    assert d["entries"] and "fake-chen-secret" not in json.dumps(d)
    assert "Secret-Chen" not in json.dumps(d)
    entry = d["entries"][0]["entry"]
    commitment = entry["orcid_commitment"]
    assert entry["authority"]["assertion"]["orcid_commitment"] == commitment
    # The person can open the commitment (the salt is on their device only).
    ident = c.config["identity"]
    assert ident["orcid"] == "fake-chen-secret"
    assert check_orcid_opening(commitment, ident["orcid"], bytes.fromhex(ident["orcid_salt"]))
    # The old ORCID subject form finds nothing.
    assert net.tc.get("/directory/orcid:fake-chen-secret").status_code == 404
    # The identity record (members only) has the commitment, not the iD.
    rec = net.tc.get(f"/identity/{c.device.subject}", headers=auth(c.device.http.token)).json()
    assert rec["orcid_commitment"] == commitment and "orcid" not in rec


def test_resolve_by_orcid_needs_member_and_opt_in(net, tmp_path):
    alice = net.join(tmp_path / "a", "fake-alice").client
    bob = net.join(tmp_path / "b", "fake-bob").client
    path = "/resolve/orcid/fake-alice"
    assert net.tc.get(path).status_code == 401
    # Default off: the answer is the same as for a person who is not a member.
    assert net.tc.get(path, headers=auth(bob.device.http.token)).status_code == 404
    assert (
        net.tc.get("/resolve/orcid/fake-nobody", headers=auth(bob.device.http.token)).status_code
        == 404
    )
    with pytest.raises(ClientError, match="findable"):
        bob.directory.lookup("fake-alice")
    assert alice.account.whoami()["findable_by_orcid"] is False
    alice.account.set_findable(True)
    assert alice.account.whoami()["findable_by_orcid"] is True
    got = net.tc.get(path, headers=auth(bob.device.http.token)).json()
    assert got == {"orcid": "fake-alice", "subject": alice.device.subject}
    assert bob.directory.lookup("fake-alice").subject == alice.device.subject
    alice.account.set_findable(False)
    assert net.tc.get(path, headers=auth(bob.device.http.token)).status_code == 404
    # Each query is in the audit table.
    audit = net.identity.people.audit(bob.device.subject)
    assert [a["answered"] for a in audit] == [False, False, False, True, True, False]
    assert all(a["viewer"] == bob.device.subject for a in audit)


def test_resolve_rate_limit(net, tmp_path):
    bob = net.join(tmp_path / "b", "fake-bob").client
    for _ in range(RESOLVES_PER_HOUR):
        net.tc.get("/resolve/orcid/fake-x", headers=auth(bob.device.http.token))
    r = net.tc.get("/resolve/orcid/fake-x", headers=auth(bob.device.http.token))
    assert r.status_code == 429
    net.clock.t += 3601
    assert (
        net.tc.get("/resolve/orcid/fake-x", headers=auth(bob.device.http.token)).status_code == 404
    )


def test_non_member_cannot_resolve(net, tmp_path):
    alice = net.join(tmp_path / "a", "fake-alice").client
    alice.account.set_findable(True)
    # Signed in with email, never claimed an invite.
    start = net.tc.post(
        "/auth/email/start",
        json={"device_key": "11" * 32, "email": "x@example.org", "nonce": "22" * 16},
    ).json()
    code = net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]
    out = net.tc.post(
        "/auth/email/verify", json={"challenge_id": start["challenge_id"], "code": code}
    ).json()
    assert is_subject(out["assertion"]["subject"])
    assert out["assertion"]["orcid_commitment"] is None
    r = net.tc.get("/resolve/orcid/fake-alice", headers=auth(out["session"]["token"]))
    assert r.status_code == 403


def test_email_member_is_findable_by_email_only(net, tmp_path):
    """ "findable" also covers the email addresses of a person. An
    email member has no ORCID iD, so no ORCID lookup finds them."""

    def code():
        return net.mailer.outbox[-1][2].split("code is ")[1].split(".")[0]

    r = net.join(tmp_path / "a", None, email="s@example.org", email_code=code)
    assert (
        r.client.account.orcid is None and r.client.config["identity"]["orcid_commitment"] is None
    )
    r.client.account.set_findable(True)
    assert net.identity.people.resolve_email(r.subject, "s@example.org")["subject"] == r.subject
    assert net.identity.orcid_account("s@example.org") is None


def test_person_makes_the_pid_and_it_never_changes(net, tmp_path):
    pid = new_pid()
    verifier, challenge = pkce()
    start = net.tc.post(
        "/auth/orcid/start",
        json={
            "code_challenge": challenge,
            "device_key": "33" * 32,
            "nonce": "44" * 16,
            "orcid_salt": "55" * 32,
            "pid": pid,
            "return_to": "urn:anagram:oob",
            "login_hint": "fake-new",
        },
    ).json()
    status, loc = net.fetch(start["authorize_url"])  # the fake ORCID redirects to the node
    assert status == 303
    page = net.tc.get(loc).text  # out of band: the node shows the one-time code
    one_time = page.split("<pre>")[1].split("</pre>")[0]
    out = net.tc.post(
        "/auth/orcid/exchange",
        json={"code": one_time, "code_verifier": verifier, "flow_id": start["flow_id"]},
    ).json()
    assert out["assertion"]["subject"] == pid
    assert out["profile"] == {"name": None, "orcid": "fake-new", "orcid_salt": "55" * 32}
    # A later join with another proposed pid keeps the first pid.
    r = net.join(tmp_path / "a", "fake-new")
    assert r.subject == pid


def test_client_refuses_a_wrong_orcid_opening(net, tmp_path):
    def evil(method, path, body, headers=None):
        out = net.transport(method, path, body, headers)
        if path == "/auth/orcid/exchange":
            out["profile"]["orcid_salt"] = "00" * 32
        return out

    with pytest.raises(ClientError, match="commitment"):
        net.join(tmp_path / "a", "fake-x", transport=evil)


def test_organizers_are_listed_by_orcid(tmp_path):
    net = make_net(tmp_path, organizers=["fake-boss"])
    boss = net.join(tmp_path / "o", "fake-boss").client
    assert boss.account.whoami()["role"] == "organizer"
    assert json.loads((tmp_path / "node" / "node.json").read_text())["organizers"] == ["fake-boss"]


def test_ui_findable_setting_and_search_by_orcid(tmp_path):
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "me")
    launched(tc)
    join_via_ui(net, svc, tc, "fake-ui-person", "UI Person")
    assert tc.get("/api/overview").json()["orcid"] == "fake-ui-person"
    tc.put("/api/settings/findable", json={"on": False}, headers=ORIGIN)
    assert tc.get("/api/overview").json()["findable_by_orcid"] is False
    assert tc.put("/api/settings/findable", json={"on": True}, headers=ORIGIN).json() == {
        "findable": True,
        "findable_by_orcid": True,
    }
    assert tc.get("/api/overview").json()["findable_by_orcid"] is True
    # A typed ORCID iD is a search result.
    found = tc.get("/api/people", params={"q": "fake-rival"}).json()
    assert found[0] == {"detail": "ORCID iD", "id": "fake-rival", "label": "ORCID iD fake-rival"}
    # The personal store sync from the UI.
    assert "pushed" in tc.post("/api/store/sync", headers=ORIGIN).json()
