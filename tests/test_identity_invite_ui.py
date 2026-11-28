"""Invite-only join in the local UI, the optional
ORCID link, the invite chain on screens, and the organizer page with no
ORCID sign-in."""

from __future__ import annotations

import time
import urllib.parse

import pytest
from conftest import make_net
from test_admin import Site
from test_ui_api import BASE, ORIGIN, launched, ui_client

from anagram.admission.app.join import join
from anagram.admission.node.reader import ReaderInvites
from anagram.admission.node.store import AdmissionStore
from anagram.core.nodeapi import NodeHTTPError
from anagram.shell.client import Client


def wait_joined(svc, tc) -> dict:
    svc.join.task.thread.join(30)
    return tc.get("/api/join").json()["status"]


def test_join_with_the_invite_only_and_an_email(tmp_path):
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "me")
    launched(tc)
    svc.join.prepare(net.invite())
    info = tc.get("/api/join").json()
    assert info["contact"] is None  # the form asks for the email address
    # The invite comes first; then the name; then a good address.
    assert "name" in tc.post("/api/join/start", json={}, headers=ORIGIN).json()["error"]
    bad = tc.post("/api/join/start", json={"name": "Ada", "email": "no"}, headers=ORIGIN)
    assert bad.status_code == 400 and "email" in bad.json()["error"]
    r = tc.post(
        "/api/join/start", json={"name": "Ada Lovelace", "email": "ada@lab.example"}, headers=ORIGIN
    )
    assert r.status_code == 200 and r.json()["authorize_url"] is None  # no ORCID page
    assert wait_joined(svc, tc)["state"] == "joined"
    ov = tc.get("/api/overview").json()
    assert ov["joined"] and ov["orcid"] is None and ov["name"] == "Ada Lovelace"
    assert ov["email"] == "ada@lab.example" and ov["findable"] is True
    assert not ov["organizer"]
    # No join waits for a code.
    r = tc.post("/api/join/code", json={"code": "12345678"}, headers=ORIGIN)
    assert r.status_code == 409
    assert tc.post("/api/join/code", json={"code": "12"}, headers=ORIGIN).status_code == 400
    # A member who is not an organizer gets no organizer link.
    assert tc.post("/api/organizer/open", headers=ORIGIN).status_code == 403


def test_link_orcid_from_the_ui(tmp_path):
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "me")
    launched(tc)
    svc.join.prepare(net.invite())
    tc.post("/api/join/start", json={"name": "Ada"}, headers=ORIGIN)
    assert wait_joined(svc, tc)["state"] == "joined"
    svc.state.update(login_hint="fake-ada-ui")  # the fake ORCID page fills it
    view = tc.post("/api/orcid/link", headers=ORIGIN).json()
    assert view["state"] == "signin" and view["authorize_url"]
    url = view["authorize_url"]
    for _ in range(5):
        if url.startswith(svc.return_to):
            break
        status, loc = net.fetch(url)
        assert status in (302, 303), (status, url)
        url = urllib.parse.urljoin(url, loc)
    r = tc.get(url.removeprefix(BASE), headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 200
    assert wait_joined(svc, tc)["state"] == "linked"
    ov = tc.get("/api/overview").json()
    assert ov["orcid"] == "fake-ada-ui"


def test_signin_again_without_orcid(tmp_path):
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "me")
    launched(tc)
    svc.join.prepare(net.invite())
    tc.post("/api/join/start", json={"name": "Ada"}, headers=ORIGIN)
    assert wait_joined(svc, tc)["state"] == "joined"
    with svc.session() as c:
        c.account.logout()
    view = tc.post("/api/signin", json={}, headers=ORIGIN).json()
    assert view["authorize_url"] is None
    assert wait_joined(svc, tc)["state"] == "joined"
    assert tc.get("/api/account").status_code == 200


def test_organizer_opens_the_page_with_a_one_time_link(tmp_path):
    site = Site(tmp_path)
    url = site.admission.create_invite(None, 7, organizer=True)["invite_url"]
    org = join(
        tmp_path / "inv-org",
        url,
        transport=site.org.device.http.transport,
        method="invite",
        display_name="Invite Organizer",
        clock=site.clock,
        open_home=Client.open,
    ).client
    assert org.account.orcid is None
    link = org.device.http.call("POST", "/admin/enter-link", {}, auth=True)["url"]
    path = link.split("/admin", 1)[1]
    r = site.tc.get("/admin" + path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/admin"
    page = site.tc.get("/admin").text
    assert "Who invited whom" in page and "Invite Organizer" in page
    assert "Invited by the node" in page and "pid:" not in page
    # One use only.
    assert site.tc.get("/admin" + path, follow_redirects=False).status_code == 403
    with pytest.raises(NodeHTTPError) as exc:
        site.member.device.http.call("POST", "/admin/enter-link", {}, auth=True)
    assert exc.value.status == 403
    assert site.tc.post("/admin/enter-link").status_code == 403


def test_lab_rows_show_who_invited(tmp_path):
    net = make_net(tmp_path)
    pi_svc, pi = ui_client(net, tmp_path / "pi")
    launched(pi)
    pi_svc.join.prepare(net.invite())
    pi.post("/api/join/start", json={"name": "Mei-Lin Chen"}, headers=ORIGIN)
    assert wait_joined(pi_svc, pi)["state"] == "joined"
    lab = pi.post("/api/labs", json={"name": "Chen Lab"}, headers=ORIGIN).json()["id"]
    with pi_svc.session() as c:
        link = c.admission.lab_invite(lab)["url"]
    m_svc, m = ui_client(net, tmp_path / "member")
    launched(m)
    m_svc.join.prepare(link)
    m.post("/api/join/start", json={"name": "Ada Okafor"}, headers=ORIGIN)
    assert wait_joined(m_svc, m)["state"] == "joined"
    with pi_svc.session() as c:
        c.labs.lab_sync()
    view = pi.get(f"/api/labs/{lab}").json()
    rows = {x["person"]["name"]: x for x in view["members"]}
    assert rows["Ada Okafor"]["invited_by"]["you"] is True
    assert rows["Mei-Lin Chen"]["invited_by"] is None


def test_reader_invite_to_an_email_has_a_code_step(tmp_path):
    net = make_net(tmp_path)
    owner = net.join_invite(tmp_path / "owner").client
    made = ReaderInvites(net.identity, AdmissionStore(net.identity.db, net.identity.lock)).create(
        owner.device.subject, {"kind": "email", "value": "r@uni.edu"}, None
    )
    svc, tc = ui_client(net, tmp_path / "reader")
    launched(tc)
    svc.join.prepare(made["invite_url"])
    info = tc.get("/api/join").json()
    assert info["contact"] == "email" and info["email_hint"] != "r@uni.edu"
    view = tc.post("/api/join/start", json={"name": "Reader"}, headers=ORIGIN).json()
    end = time.monotonic() + 10
    while view["state"] != "code" and time.monotonic() < end:
        view = tc.get("/api/join").json()["status"]
    assert view["state"] == "code" and view["email_hint"]
    code = net.mailer.outbox[-1][2].split("code is ")[1][:8]
    assert tc.post("/api/join/code", json={"code": code}, headers=ORIGIN).status_code == 200
    assert wait_joined(svc, tc)["state"] == "joined"
    assert tc.get("/api/overview").json()["email"] == "r@uni.edu"
