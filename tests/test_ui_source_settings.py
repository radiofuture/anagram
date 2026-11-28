# ruff: noqa: F811, S105, S106 - fixtures from test_ui_sources_api; test values, not secrets
"""The lab source settings sections in the local UI:
`oauth_clients` (the Google and Notion clients of a lab) and `sources` (the
kinds that the lab space permits, and the default space). The node is the
in-process fake of conftest. No network."""

from __future__ import annotations

import json

from test_source_space import kinds, make_lab
from test_ui_api import ORIGIN
from test_ui_sources_api import member  # noqa: F401 - fixture

from anagram.network.groups.app.labrecords import LabSpace
from anagram.network.groups.app.labs import Labs

GOOGLE_ID = "123456789012-abcdefghij0123456789abcdefghij01.apps.googleusercontent.com"
NOTION_ID = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d"


def put_client(tc, lab_id: str, provider: str, **body):
    return tc.put(f"/api/source-settings/{lab_id}/clients/{provider}", json=body, headers=ORIGIN)


def test_settings_need_the_cookie(member):
    svc, tc = member
    tc.cookies.clear()
    assert tc.get("/api/source-settings").status_code == 401
    r = put_client(tc, "x", "google", client_id=GOOGLE_ID, client_secret="s")
    assert r.status_code == 401


def test_no_lab_gives_an_empty_list(member):
    _, tc = member
    out = tc.get("/api/source-settings").json()
    assert out["labs"] == []
    assert "gmail" not in {k["kind"] for k in out["kinds"]}  # mail stays private
    assert {"folder", "gdrive", "notion"} <= {k["kind"] for k in out["kinds"]}


def test_a_lab_admin_sets_the_google_client(member):
    svc, tc = member
    lab_id = make_lab(svc)
    assert not kinds(tc)["gdrive"]["available"]
    row = tc.get("/api/source-settings").json()["labs"][0]
    assert row["can_edit"] is True and row["clients"] == {"google": None, "notion": None}
    r = put_client(tc, lab_id, "google", client_id=GOOGLE_ID, client_secret="GOCSPX-secret-1")
    assert r.status_code == 200, r.text
    assert r.json()["clients"]["google"] == {"client_id": GOOGLE_ID, "has_secret": True}
    # The secret is in the record, never in an answer to the page.
    assert "GOCSPX-secret-1" not in json.dumps(tc.get("/api/source-settings").json())
    with svc.session() as c:
        assert (
            c.lab_space.lab_policy(lab_id).oauth_clients["google"]["client_secret"]
            == "GOCSPX-secret-1"
        )
    # The kinds of Google are available at once.
    by = kinds(tc)
    assert by["gdrive"]["available"] and by["gmail"]["available"]
    assert not by["notion"]["available"]
    # A new ID with no secret needs the secret; the same ID keeps it.
    other = "999999999999-zzzzzzzzzz0123456789abcdefghij01.apps.googleusercontent.com"
    r = put_client(tc, lab_id, "google", client_id=other)
    assert r.status_code == 400 and r.json()["code"] == "no_secret"
    assert put_client(tc, lab_id, "google", client_id=GOOGLE_ID).status_code == 200
    with svc.session() as c:
        assert (
            c.lab_space.lab_policy(lab_id).oauth_clients["google"]["client_secret"]
            == "GOCSPX-secret-1"
        )
    # Notion is a second client; Google stays.
    r = put_client(tc, lab_id, "notion", client_id=NOTION_ID, client_secret="secret_abc")
    assert set(k for k, v in r.json()["clients"].items() if v) == {"google", "notion"}
    # Remove the Google client: the kinds are not set up again.
    r = tc.delete(f"/api/source-settings/{lab_id}/clients/google", headers=ORIGIN)
    assert r.json()["clients"]["google"] is None and r.json()["clients"]["notion"]
    assert not kinds(tc)["gdrive"]["available"]


def test_a_wrong_paste_says_what_the_id_looks_like(member):
    svc, tc = member
    lab_id = make_lab(svc)
    r = put_client(tc, lab_id, "google", client_id="GOCSPX-oops", client_secret="x")
    assert r.status_code == 400 and r.json()["code"] == "bad_client_id"
    assert "apps.googleusercontent.com" in r.json()["error"]
    r = put_client(tc, lab_id, "google", client_id=GOOGLE_ID, client_secret="two words")
    assert r.json()["code"] == "bad_secret"
    assert put_client(tc, lab_id, "github", client_id="x").status_code == 404
    assert (
        put_client(tc, "f" * 32, "google", client_id=GOOGLE_ID, client_secret="s").status_code
        == 403
    )


def test_a_member_reads_and_cannot_change(member, monkeypatch):
    svc, tc = member
    lab_id = make_lab(svc)
    real = Labs.lab_list
    monkeypatch.setattr(
        Labs, "lab_list", lambda self: [{**lab, "role": "member"} for lab in real(self)]
    )
    assert tc.get("/api/source-settings").json()["labs"][0]["can_edit"] is False
    monkeypatch.setattr(LabSpace, "lab_set_settings", _refused)
    r = put_client(tc, lab_id, "google", client_id=GOOGLE_ID, client_secret="s")
    assert (
        r.status_code == 403 and r.json()["error"] == "Your role in this lab does not permit this."
    )


def _refused(self, lab_id, changes):
    from anagram.network.groups.app.labroster import LabError

    raise LabError("Your role in this lab does not permit this.")


def test_the_lab_rules_for_sources(member):
    svc, tc = member
    lab_id = make_lab(svc)
    url = f"/api/source-settings/{lab_id}/sources"
    r = tc.put(url, json={"allowed_kinds": ["obsidian"], "lab_default": "lab"}, headers=ORIGIN)
    assert r.json()["sources"] == {"allowed_kinds": ["obsidian"], "lab_default": "lab"}
    by = kinds(tc)
    assert by["obsidian"]["default_space"] == f"lab:{lab_id}"
    assert by["folder"]["labs"] == []
    # null permits each kind; the default stays.
    r = tc.put(url, json={"allowed_kinds": None}, headers=ORIGIN)
    assert r.json()["sources"] == {"allowed_kinds": None, "lab_default": "lab"}
    assert kinds(tc)["folder"]["labs"]
    for bad in ({"allowed_kinds": ["gmail"]}, {"lab_default": "everyone"}, {}):
        assert tc.put(url, json=bad, headers=ORIGIN).status_code == 400
