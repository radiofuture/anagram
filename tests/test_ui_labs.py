"""Lab routes of the local UI (plan R2 5.5, step S9a).

Two people use the UI on one in-process node: a PI (Mei-Lin Chen) and a
person who joins with a lab invite link (Ada Okafor). Each route is called
through the guard of `create_ui_app` (cookie, Origin).
"""

from __future__ import annotations

import json

import pytest
from conftest import make_net
from test_ui_api import ORIGIN, join_via_ui, launched, ui_client


def _bus(tc):
    seen: list[tuple[str, dict]] = []
    tc.app.state.ctx.bus.tap(lambda e: seen.append((e.type, e.data)))
    return seen


@pytest.fixture
def pair(tmp_path):
    net = make_net(tmp_path)
    pi_svc, pi = ui_client(net, tmp_path / "pi")
    launched(pi)
    join_via_ui(net, pi_svc, pi, "fake-0000-0001-lab-pi", "Mei-Lin Chen")
    m_svc, m = ui_client(net, tmp_path / "member")
    launched(m)
    join_via_ui(net, m_svc, m, "fake-0000-0002-lab-mem", "Ada Okafor")
    return net, (pi_svc, pi), (m_svc, m)


def _sync(svc) -> None:
    with svc.session() as c:
        c.labs.lab_sync()


def _clean(text: str, svc) -> None:
    """No response holds a path, a device key, or a record ID."""
    with svc.session() as c:
        device = c.device.device_key().public_bytes().hex()
    assert str(svc.home) not in text
    assert device not in text
    assert "record_id" not in text and "key_id" not in text and "content_key" not in text


def test_lab_flow_through_the_ui(pair):
    _, (pi_svc, pi), (m_svc, m) = pair
    seen = _bus(pi)
    assert pi.get("/api/labs/mine").json() == []
    view = pi.post("/api/labs", json={"name": "Chen Lab"}, headers=ORIGIN).json()
    lab = view["id"]
    assert view["name"] == "Chen Lab" and view["role"] == "pi"
    assert view["can"]["invite"] and view["can"]["invite_admin"] and not view["can"]["leave"]
    assert [x["person"]["name"] for x in view["members"]] == ["Mei-Lin Chen"]
    assert view["members"][0]["you"] and view["members"][0]["joined_at"].endswith("Z")
    assert ("lab.members", {"change": "joined", "lab": lab}) in seen
    mine = pi.get("/api/labs/mine").json()
    assert mine == [
        {
            "i_lead": True,
            "id": lab,
            "members": 1,
            "name": "Chen Lab",
            "role": "pi",
            "rotation_due": False,
        }
    ]

    # A second lab with the same name is refused: the two could not be told apart.
    again = pi.post("/api/labs", json={"name": " chen lab "}, headers=ORIGIN)
    assert again.status_code == 409 and "another name" in again.json()["error"]
    assert len(pi.get("/api/labs/mine").json()) == 1

    inv = pi.post(f"/api/labs/{lab}/invites", json={"max_uses": 2}, headers=ORIGIN).json()
    assert inv["url"].split("#")[0].endswith("/join") and inv["expires_at"]
    assert ("lab.invites", {"lab": lab}) in seen
    view = pi.get(f"/api/labs/{lab}").json()
    assert [(i["uses"], i["max_uses"], i["role"]) for i in view["invites"]] == [(0, 2, "member")]
    assert view["invites"][0]["by"]["name"] == "Mei-Lin Chen"

    pre = m.get("/api/labs/invite", params={"url": inv["url"]}).json()
    assert pre["lab"] == "Chen Lab" and pre["role"] == "member" and pre["open"]
    assert pre["by"] == "Mei-Lin Chen" and pre["host"]
    assert pre["member"] is False
    got = m.post("/api/labs/join", json={"url": inv["url"]}, headers=ORIGIN).json()
    assert got == {"id": lab, "name": "Chen Lab", "role": "member"}
    assert m.get("/api/labs/invite", params={"url": inv["url"]}).json()["member"] is True
    mv = m.get(f"/api/labs/{lab}").json()
    assert mv["role"] == "member" and not mv["can"]["invite"] and mv["can"]["leave"]
    assert mv["invites"] == []  # a member does not see the invites
    view = pi.get(f"/api/labs/{lab}").json()
    assert sorted(x["person"]["name"] for x in view["members"]) == ["Ada Okafor", "Mei-Lin Chen"]
    assert view["invites"][0]["uses"] == 1

    # Settings: the PI writes a section; a member reads it.
    st = pi.get(f"/api/labs/{lab}/settings").json()
    assert st["can_edit"] and st["settings"]["matching"] == {"enabled": True}
    assert st["editors"] == ["Mei-Lin Chen"]
    assert {"kind": "folder", "label": "Folder"} in st["source_kinds"]
    st = pi.put(
        f"/api/labs/{lab}/settings", json={"matching": {"enabled": False}}, headers=ORIGIN
    ).json()
    assert st["settings"]["matching"] == {"enabled": False}
    assert st["updated_by"]["name"] == "Mei-Lin Chen"
    assert any(t == "lab.settings" for t, _ in seen)
    _sync(m_svc)
    ms = m.get(f"/api/labs/{lab}/settings").json()
    assert not ms["can_edit"] and ms["settings"]["matching"] == {"enabled": False}
    r = m.put(f"/api/labs/{lab}/settings", json={"matching": {"enabled": True}}, headers=ORIGIN)
    assert r.status_code == 400 and "role" in r.json()["error"]

    # Lab space: a note of the member reaches the PI.
    row = m.post(
        f"/api/labs/{lab}/space",
        json={"note": {"title": "Buffer recipe", "text": "Tris 50 mM, pH 7.4"}},
        headers=ORIGIN,
    ).json()
    assert row["title"] == "Buffer recipe" and row["yours"] and row["kind"] == "note"
    _sync(pi_svc)
    space = pi.get(f"/api/labs/{lab}/space").json()
    assert [(i["title"], i["author"]["name"], i["yours"]) for i in space["items"]] == [
        ("Buffer recipe", "Ada Okafor", False)
    ]
    item = pi.get(f"/api/labs/{lab}/space/{row['id']}").json()
    assert item["text"] == "Tris 50 mM, pH 7.4" and item["can_remove"]
    _clean(json.dumps([space, item, view, st]), pi_svc)
    assert m.delete(f"/api/labs/{lab}/space/{row['id']}", headers=ORIGIN).json() == {
        "removed": True
    }
    assert m.get(f"/api/labs/{lab}/space").json()["items"] == []

    # Roles, then removal.
    view = pi.put(
        f"/api/labs/{lab}/members/{got_pid(view, 'Ada Okafor')}",
        json={"role": "admin"},
        headers=ORIGIN,
    ).json()
    assert {x["person"]["name"]: x["role"] for x in view["members"]}["Ada Okafor"] == "admin"
    view = pi.delete(
        f"/api/labs/{lab}/members/{got_pid(view, 'Ada Okafor')}", headers=ORIGIN
    ).json()
    assert [x["person"]["name"] for x in view["members"]] == ["Mei-Lin Chen"]
    assert any(t == "lab.members" and d["change"] == "removed" for t, d in seen)
    assert m.get(f"/api/labs/{lab}").status_code == 404


def got_pid(view: dict, name: str) -> str:
    return next(x["person"]["id"] for x in view["members"] if x["person"]["name"] == name)


def test_leave_and_the_pi_cannot_leave(pair):
    _, (_, pi), (m_svc, m) = pair
    lab = pi.post("/api/labs", json={"name": "Okafor Lab"}, headers=ORIGIN).json()["id"]
    url = pi.post(f"/api/labs/{lab}/invites", json={}, headers=ORIGIN).json()["url"]
    m.post("/api/labs/join", json={"url": url}, headers=ORIGIN)
    seen = _bus(m)
    r = pi.post(f"/api/labs/{lab}/leave", headers=ORIGIN)
    assert r.status_code == 400 and "PI" in r.json()["error"]
    assert m.post(f"/api/labs/{lab}/leave", headers=ORIGIN).json() == {"left": True}
    assert ("lab.removed", {"lab": lab, "name": "Okafor Lab"}) in seen
    assert m.get("/api/labs/mine").json() == []
    # A used single-use link: one sentence, one next step.
    r = m.post("/api/labs/join", json={"url": url}, headers=ORIGIN)
    assert r.status_code == 400 and "Ask" in r.json()["error"]


def test_pending_invite_and_errors(pair):
    _, (_, pi), (m_svc, m) = pair
    assert m.get("/api/labs/invite").status_code == 404  # no pending invite
    lab = pi.post("/api/labs", json={"name": "Reyes Lab"}, headers=ORIGIN).json()["id"]
    url = pi.post(f"/api/labs/{lab}/invites", json={"role": "admin"}, headers=ORIGIN).json()["url"]
    m_svc.state.update(pending_invite={"kind": "lab", "url": url})
    pre = m.get("/api/labs/invite").json()
    assert pre["lab"] == "Reyes Lab" and pre["role"] == "admin"
    got = m.post("/api/labs/join", json={}, headers=ORIGIN).json()
    assert got["role"] == "admin"
    assert m_svc.state.get("pending_invite") is None
    assert (
        m.get("/api/labs/invite", params={"url": "https://x.example/join#abc"}).status_code == 400
    )
    assert pi.post("/api/labs", json={"name": " "}, headers=ORIGIN).status_code == 400
    r = pi.post(f"/api/labs/{lab}/invites", json={"max_uses": 99}, headers=ORIGIN)
    assert r.status_code == 400 and "25" in r.json()["error"]
    # An admin cannot make an admin invite.
    r = m.post(f"/api/labs/{lab}/invites", json={"role": "admin"}, headers=ORIGIN)
    assert r.status_code == 400
    # Revoke closes the link.
    inv = pi.post(f"/api/labs/{lab}/invites", json={}, headers=ORIGIN).json()
    view = pi.delete(f"/api/labs/{lab}/invites/{inv['id']}", headers=ORIGIN).json()
    assert inv["id"] not in {i["id"] for i in view["invites"]}
    assert m.get("/api/labs/invite", params={"url": inv["url"]}).json()["open"] is False


def test_lab_routes_need_the_cookie(tmp_path):
    net = make_net(tmp_path)
    _, tc = ui_client(net, tmp_path / "me")
    for method, path in (
        ("POST", "/api/labs"),
        ("POST", "/api/labs/join"),
        ("GET", "/api/labs/invite"),
        ("GET", "/api/labs/lab-0123456789abcdef"),
        ("GET", "/api/labs/lab-0123456789abcdef/space"),
        ("PUT", "/api/labs/lab-0123456789abcdef/settings"),
    ):
        assert tc.request(method, path, headers=ORIGIN, json={}).status_code == 401, path
    launched(tc)
    evil = {"Origin": "http://evil.example"}
    assert tc.post("/api/labs", json={"name": "X"}, headers=evil).status_code == 403
    # Not joined: the join route asks for the sign-in.
    assert tc.post("/api/labs/join", json={}, headers=ORIGIN).json() == {"signin": True}
