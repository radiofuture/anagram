"""The "Labs" section of the organizer page (plan R2 5.4, step S11)."""

from __future__ import annotations

import json

import pytest
from conftest import NODE_URL
from test_admin import CANARY, MEMBER, ORG, Site, csrf_of

from anagram.network.groups.app.labrecords import LabItemDraft
from anagram.network.groups.app.labroster import LabError

SAME = {"Origin": NODE_URL}


@pytest.fixture
def site(tmp_path):
    s = Site(tmp_path)
    s.lab_id = s.member.lab_roster.labcache.labs()[0]
    s.member.lab_space.lab_publish(s.lab_id, LabItemDraft("note", CANARY, CANARY, {"name": "x.md"}))
    return s


def signed_in(site) -> str:
    site.orcid_login(ORG)
    return csrf_of(site.tc.get("/admin").text)


def test_rows_need_the_session_and_hold_no_content(site):
    assert site.tc.get("/admin/api/labs").status_code == 403
    assert site.tc.get("/admin/api/status").status_code == 403
    signed_in(site)
    rows = site.tc.get("/admin/api/labs").json()
    [row] = rows
    assert set(row) == {
        "admins",
        "bytes",
        "created_at",
        "epoch",
        "lab_id",
        "last_change_at",
        "members",
        "name",
        "open_invites",
        "quota",
        "records",
        "suspended",
    }
    assert row["name"] == "Varga Lab" and row["members"] == 1 and row["admins"] == 1
    assert row["records"] == 2 and row["bytes"] > 0 and row["epoch"] == 1
    assert row["suspended"] is False and row["created_at"] and row["last_change_at"]
    text = json.dumps(rows) + site.tc.get("/admin/api/status").text
    assert CANARY not in text and site.member.device.subject not in text
    assert site.tc.get("/admin/api/status").json()["labs"] == rows


def test_member_session_is_refused(site):
    r = site.orcid_login(MEMBER)
    assert r.status_code == 403
    assert site.tc.get("/admin/api/labs").status_code == 403


def test_suspend_stops_writes_and_csrf_is_checked(site):
    csrf = signed_in(site)
    path = f"/admin/api/labs/{site.lab_id}"
    # No CSRF value, a wrong value, another origin, or no origin: refused.
    assert site.tc.post(path, json={"suspended": True}, headers=SAME).status_code == 403
    assert (
        site.tc.post(path, json={"suspended": True, "csrf": "x"}, headers=SAME).status_code == 403
    )
    evil = {"Origin": "https://evil.example"}
    assert (
        site.tc.post(path, json={"suspended": True, "csrf": csrf}, headers=evil).status_code == 403
    )
    assert site.tc.post(path, json={"suspended": True, "csrf": csrf}).status_code == 403
    row = site.tc.post(path, json={"suspended": True, "csrf": csrf}, headers=SAME).json()
    assert row["suspended"] is True
    with pytest.raises(LabError):
        site.member.lab_space.lab_publish(site.lab_id, LabItemDraft("note", "New", "text", {}))
    site.member.labs.lab_sync(site.lab_id)  # members still read
    assert [v["title"] for v in site.member.lab_space.lab_items(site.lab_id)] == [CANARY]
    row = site.tc.post(path, json={"suspended": False, "csrf": csrf}, headers=SAME).json()
    assert row["suspended"] is False
    site.member.lab_space.lab_publish(site.lab_id, LabItemDraft("note", "New", "text", {}))
    # The quota.
    row = site.tc.post(path, json={"quota": 5 << 20, "csrf": csrf}, headers=SAME).json()
    assert row["quota"] == 5 << 20
    r = site.tc.post(path, json={"quota": 10, "csrf": csrf}, headers=SAME)
    assert r.status_code == 400
    r = site.tc.post(
        "/admin/api/labs/lab-0000000000000000", json={"quota": 5 << 20, "csrf": csrf}, headers=SAME
    )
    assert r.status_code == 404


def test_invite_route(site):
    csrf = signed_in(site)
    assert site.tc.post("/admin/api/invites", json={"days": 3}, headers=SAME).status_code == 403
    out = site.tc.post("/admin/api/invites", json={"days": 3, "csrf": csrf}, headers=SAME).json()
    assert out["invite_url"].startswith(NODE_URL) and "/join#" in out["invite_url"]


def test_page_loads_the_script_from_the_same_origin(site):
    csrf = signed_in(site)
    page = site.tc.get("/admin")
    assert "<script type=module src=/brand/node/admin_labs.js></script>" in page.text
    assert f"id=ag-admin-labs data-csrf='{csrf}'" in page.text
    assert "script-src 'self'" in page.headers["content-security-policy"]
    js = site.tc.get("/brand/node/admin_labs.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert "innerHTML" not in js.text
