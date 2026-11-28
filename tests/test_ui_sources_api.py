"""Source routes of the local UI (plan R3 section 3.11) and the source events
in the table `source_event`. The node is the in-process fake of conftest. No
network."""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path

import pytest
from conftest import make_net
from sourcekit import browse, loopback_only  # noqa: F401 - fixture
from test_ui_api import ORIGIN, join_via_ui, launched, ui_client

from anagram.local.sources import http as http_mod
from anagram.local.sources import source_state as ss
from anagram.local.sources.fake_google import FakeGoogle
from anagram.shell.ui.errors import UIError

ORCID = "0000-0002-1825-0097"
FIXTURE = Path(__file__).parent / "fixtures" / "vault"


@pytest.fixture
def member(tmp_path):
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "me")
    launched(tc)
    join_via_ui(net, svc, tc, ORCID, "Test Member")
    return svc, tc


@pytest.fixture
def places(tmp_path) -> dict[str, Path]:
    work = tmp_path / "work"
    (work / "notes").mkdir(parents=True)
    (work / "notes" / "plan.md").write_text("# Plan\n\nA plan about nanodiscs.\n")
    shutil.copytree(FIXTURE, work / "Lab vault")
    return {"work": work, "vault": work / "Lab vault"}


def events(svc, topic: str | None = None) -> list[dict]:
    with svc.session(index=True) as (_, idx):
        rows = ss.events_after(idx.store, 0, limit=2000)
    return [r for r in rows if topic is None or r["topic"] == topic]


def add(tc, **body) -> dict:
    r = tc.post("/api/sources", json=body, headers=ORIGIN)
    assert r.status_code == 200, r.text
    return r.json()


def row(tc, sid: str) -> dict:
    return tc.get(f"/api/sources/{sid}").json()


def test_new_routes_need_the_cookie(tmp_path):
    net = make_net(tmp_path)
    _, tc = ui_client(net, tmp_path / "me")
    sid = "0" * 32
    for method, path in (
        ("GET", "/api/source-kinds"),
        ("GET", f"/api/sources/{sid}"),
        ("PATCH", f"/api/sources/{sid}"),
        ("POST", f"/api/sources/{sid}/pause"),
        ("POST", f"/api/sources/{sid}/resume"),
        ("POST", f"/api/sources/{sid}/sync"),
    ):
        r = tc.request(method, path, json={}, headers=ORIGIN)
        assert r.status_code == 401, (method, path)


def test_source_kinds(member):
    _, tc = member
    kinds = tc.get("/api/source-kinds").json()["kinds"]
    by = {k["kind"]: k for k in kinds}
    assert list(by)[:5] == ["folder", "obsidian", "git", "zotero_file", "orcid_works"]
    assert "gdrive" in by
    assert by["obsidian"] == {
        "auth": "none",
        "available": True,
        "choose": "path",
        "kind": "obsidian",
        "label": "Obsidian vault",
        "provider": None,
        "spaces": ["private", "lab"],
        "unavailable_reason": None,
        "default_space": "private",
        "lab_refused": None,
        "labs": [],
    }
    assert "github" not in by and "labspace" not in by


def test_add_an_obsidian_vault_and_read_it(member, places):
    svc, tc = member
    out = add(tc, kind="obsidian", path=str(places["vault"]))
    assert out["added"] == 1 and out["found"] == "1 Obsidian vault"
    sid = out["sources"][0]
    src = row(tc, sid)
    assert src["label"] == "Lab vault"  # no full path
    assert (src["kind"], src["status"], src["space"], src["paused"]) == (
        "obsidian",
        "live",
        "private",
        False,
    )
    assert src["items"] == 10 and src["own"] is True and src["fault"] is None
    assert src["assistant"] is True
    assert src["include"] == {"exclude": []} and src["account"] is None
    added = events(svc, "source.added")
    assert [e["data"]["source"]["id"] for e in added] == [sid]
    assert str(places["vault"]) not in json.dumps(events(svc))
    # The same vault is not added two times.
    assert add(tc, kind="obsidian", path=str(places["vault"]))["added"] == 0
    r = tc.post(
        "/api/sources",
        json={"kind": "obsidian", "path": str(places["work"] / "notes")},
        headers=ORIGIN,
    )
    assert r.status_code == 400 and r.json()["code"] == "no_vault"


def test_a_folder_with_a_vault_inside_gives_two_sources(member, places):
    svc, tc = member
    out = add(tc, kind="folder", path=str(places["work"]))  # the old request body
    assert out["added"] == 2
    rows = tc.get("/api/sources").json()["sources"]
    by_kind = {r["kind"]: r for r in rows}
    assert set(by_kind) == {"folder", "obsidian"}
    folder = row(tc, by_kind["folder"]["id"])
    assert folder["include"] == {"exclude": ["Lab vault"]}
    assert folder["items"] == 1  # the vault is not read two times
    assert "details" not in by_kind["folder"]  # no stream id in the list


def test_list_row_has_the_new_keys(member, places):
    _, tc = member
    add(tc, kind="folder", path=str(places["work"] / "notes"))
    data = tc.get("/api/sources").json()
    assert set(data) == {"helper", "last_refresh", "sources"}
    r = data["sources"][0]
    for key in (
        "status",
        "paused",
        "space",
        "account",
        "phase",
        "progress",
        "fault",
        "last_sync_at",
        "own",
        "assistant",
        "label",
        "kind",
        "kind_label",
        "items",
        "indexed",
    ):
        assert key in r, key
    assert set(r["progress"]) == {"at", "done", "skipped", "total"}


def test_an_unknown_or_old_kind_name_is_refused(member):
    """The old names `zotero` and `orcid` were removed with the other
    legacy paths before the open-source release."""
    _, tc = member
    for kind in ("nothing", "zotero", "orcid"):
        r = tc.post("/api/sources", json={"kind": kind}, headers=ORIGIN)
        assert r.status_code == 400 and r.json()["code"] == "unknown_kind"


def test_patch_label_prefs_and_include(member, places):
    svc, tc = member
    sid = add(tc, kind="obsidian", path=str(places["vault"]))["sources"][0]
    r = tc.patch(
        f"/api/sources/{sid}",
        json={
            "label": " Notes ",
            "assistant": False,
            "include": {"exclude": ["Archive", "Templates"]},
        },
        headers=ORIGIN,
    )
    assert r.status_code == 200, r.text
    src = r.json()
    assert src["label"] == "Notes"
    assert src["assistant"] is False
    assert src["include"] == {"exclude": ["Archive", "Templates"]}
    assert src["items"] == 7  # a narrower choice removes its items now
    for bad in (
        {"label": ""},
        {"assistant": "yes"},
        {"include": {"exclude": ["../x"]}},
        {"space": "team"},
        {"filter": {"mode": "all"}},
    ):
        r = tc.patch(f"/api/sources/{sid}", json=bad, headers=ORIGIN)
        assert r.status_code == 400, bad
    assert row(tc, sid)["label"] == "Notes"  # nothing of a refused call is stored


def test_space(member, places):
    svc, tc = member
    sid = add(tc, kind="folder", path=str(places["work"] / "notes"))["sources"][0]
    r = tc.patch(f"/api/sources/{sid}", json={"space": "private"}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["space"] == "private"
    # A lab space needs the lab policy of R2 (S6). A lab that this person is
    # not in has no policy on this computer.
    r = tc.patch(f"/api/sources/{sid}", json={"space": "lab:abc"}, headers=ORIGIN)
    assert r.status_code == 409 and r.json()["code"] == "space_unavailable"
    # In a lab of the person, the lab policy decides.
    with svc.session() as c:
        lab_id = c.labs.lab_create("My Lab")["lab_id"]
    r = tc.patch(f"/api/sources/{sid}", json={"space": f"lab:{lab_id}"}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["space"] == f"lab:{lab_id}"
    with svc.session() as c:
        c.lab_space.lab_set_settings(lab_id, {"sources": {"allowed_kinds": ["obsidian"]}})
    r = tc.patch(f"/api/sources/{sid}", json={"space": f"lab:{lab_id}"}, headers=ORIGIN)
    assert r.status_code == 403 and r.json()["code"] == "space_refused"
    r = tc.patch(f"/api/sources/{sid}", json={"space": "private"}, headers=ORIGIN)
    assert r.status_code == 200  # a private source is never refused
    # `POST /api/sources` of `shell/ui/server.py` gives only `kind` and `path` to
    # the service (build notes, S5); the service checks the space itself.
    with pytest.raises(UIError) as err:
        svc.sources.add({"kind": "folder", "path": str(places["vault"]), "space": "lab:abc"})
    assert err.value.status == 409


def test_pause_resume_sync(member, places):
    svc, tc = member
    notes = places["work"] / "notes"
    sid = add(tc, kind="folder", path=str(notes))["sources"][0]
    paused = tc.post(f"/api/sources/{sid}/pause", headers=ORIGIN).json()
    assert paused["status"] == "paused" and paused["paused"] is True
    (notes / "new.md").write_text("# New\n")
    tc.post("/api/sources/refresh", headers=ORIGIN)
    assert row(tc, sid)["items"] == 1  # a paused source is not read
    r = tc.post(f"/api/sources/{sid}/sync", headers=ORIGIN)
    assert r.status_code == 409 and r.json()["code"] == "paused"
    resumed = tc.post(f"/api/sources/{sid}/resume", headers=ORIGIN).json()
    assert resumed["status"] == "live" and resumed["paused"] is False
    synced = tc.post(f"/api/sources/{sid}/sync", headers=ORIGIN).json()
    assert synced["items"] == 2
    states = [e["data"] for e in events(svc, "source.state")]
    assert [s["status"] for s in states][-2:] == ["paused", "live"]


def test_fault_has_one_sentence_and_one_action(member, places):
    _, tc = member
    notes = places["work"] / "notes"
    sid = add(tc, kind="folder", path=str(notes))["sources"][0]
    shutil.rmtree(notes)
    tc.post("/api/sources/refresh", headers=ORIGIN)
    src = row(tc, sid)
    assert src["status"] == "attention"
    assert src["fault"] == {
        "action": "choose",
        "code": "not_found",
        "message": "This folder is not there.",
        "retry_at": None,
    }
    assert src["error"] == "This folder is not there."
    assert str(notes) not in json.dumps(src)
    notes.mkdir()
    assert tc.post(f"/api/sources/{sid}/sync", headers=ORIGIN).json()["status"] == "live"


def test_unknown_source(member):
    _, tc = member
    assert tc.get("/api/sources/" + "f" * 32).status_code == 404
    assert tc.get("/api/sources/not-an-id").status_code == 404
    r = tc.post("/api/sources/" + "f" * 32 + "/pause", headers=ORIGIN)
    assert r.status_code == 404 and r.json()["code"] == "not_found"


def test_source_events_do_not_go_to_the_bus():
    """The sources part writes its events to the table `source_event`; a
    bridge moves them to the bus (`shell/ui/bridge.py`)."""
    ui = Path(__file__).parents[1] / "src" / "anagram" / "shell" / "ui"
    for name in ("sources.py", "connections.py", "lab_sources.py", "source_kinds.py"):
        assert "ui.publish" not in (ui / name).read_text(), name
    static = Path(__file__).parents[1] / "src" / "anagram" / "shell" / "ui" / "static"
    for f in static.rglob("*.js"):
        assert "details.stream" not in f.read_text(), f


# ------------------------------------------------------------------ accounts
# Step S7. The sign-in goes through the real loopback receiver on 127.0.0.1
# (fixture `loopback_only`) and `FakeGoogle`. No call reaches Google.


def wait_flow(tc, fid: str, timeout: float = 5.0) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        st = tc.get(f"/api/accounts/connect/{fid}").json()
        if st["state"] != "waiting":
            return st
        time.sleep(0.02)
    raise AssertionError("the sign-in did not end")


@pytest.fixture
def google(member, monkeypatch, loopback_only):  # noqa: F811
    """A member with a developer OAuth client file and `FakeGoogle` as the
    transport of contract v2 sources."""
    svc, tc = member
    fake = FakeGoogle()
    monkeypatch.setattr(http_mod, "default_http", lambda: fake)
    (svc.home / "oauth-clients.json").write_text(
        json.dumps({"google": {"client_id": fake.client_id, "client_secret": fake.client_secret}})
    )
    opened: list[str] = []
    svc.connections.open_browser = opened.append
    return svc, tc, fake, opened


def sign_in(tc, fake, opened, **body) -> dict:
    r = tc.post("/api/accounts/connect", json={"kind": "gdrive", **body}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["expires_in"] == 300 and opened[-1] == out["url"]
    assert browse(fake.authorize(out["url"]))[0] == 200
    return wait_flow(tc, out["flow"])


def test_account_routes_need_the_cookie(tmp_path):
    net = make_net(tmp_path)
    _, tc = ui_client(net, tmp_path / "me")
    for method, path in (
        ("GET", "/api/accounts"),
        ("POST", "/api/accounts/connect"),
        ("GET", "/api/accounts/connect/" + "0" * 32),
        ("POST", "/api/accounts/connect/" + "0" * 32 + "/cancel"),
        ("DELETE", "/api/accounts/" + "0" * 32),
    ):
        assert tc.request(method, path, json={}, headers=ORIGIN).status_code == 401, path


def test_connect_with_no_client_is_not_set_up(member, loopback_only):  # noqa: F811
    _, tc = member
    r = tc.post("/api/accounts/connect", json={"kind": "gdrive"}, headers=ORIGIN)
    assert r.status_code == 409
    assert r.json() == {
        "code": "client_missing",
        "error": "Not set up for this lab. Ask your lab admin.",
    }
    r = tc.post("/api/accounts/connect", json={"kind": "folder"}, headers=ORIGIN)
    assert r.status_code == 400


def test_connect_a_google_account(google, caplog):
    caplog.set_level(logging.DEBUG)
    svc, tc, fake, opened = google
    st = sign_in(tc, fake, opened)
    assert st["state"] == "done"
    assert st["account"]["label"] == fake.email and st["account"]["provider"] == "google"
    accounts = tc.get("/api/accounts").json()["accounts"]
    assert accounts == [{**st["account"], "sources": []}]
    flows = [e["data"]["state"] for e in events(svc, "oauth.flow")]
    assert flows == ["waiting", "done"]
    assert [e["data"]["status"] for e in events(svc, "account.state")] == ["ok"]
    # Redaction: no token in an event, a log record, a config, or an answer.
    with svc.session(index=True) as (_, idx):
        rows = ss.events_after(idx.store, 0, limit=2000)
        stored = idx.credentials.tokens(accounts[0]["id"])
    texts = [
        json.dumps(rows),
        caplog.text,
        (svc.home / "config.json").read_text(),
        json.dumps(accounts),
    ]
    for secret in (stored.access_token, stored.refresh_token, fake.client_secret):
        assert all(secret not in t for t in texts)
    # Disconnect: the grant is revoked and the token is gone.
    acct = accounts[0]["id"]
    r = tc.request("DELETE", f"/api/accounts/{acct}", json={}, headers=ORIGIN)
    assert r.json() == {"removed_sources": 0, "revoked": True}
    assert fake.revoked == [stored.refresh_token]
    assert tc.get("/api/accounts").json()["accounts"] == []
    assert svc.keystore().list("acct-") == []


def test_connect_denied_and_cancelled(google):
    _, tc, fake, opened = google
    r = tc.post("/api/accounts/connect", json={"kind": "gdrive"}, headers=ORIGIN).json()
    browse(fake.authorize(r["url"], deny=True))
    st = wait_flow(tc, r["flow"])
    assert st == {"error": "You did not give access. Nothing was connected.", "state": "denied"}
    r = tc.post("/api/accounts/connect", json={"kind": "gdrive"}, headers=ORIGIN).json()
    assert tc.post(f"/api/accounts/connect/{r['flow']}/cancel", headers=ORIGIN).json() == {}
    assert wait_flow(tc, r["flow"])["state"] == "expired"
    assert tc.get("/api/accounts/connect/" + "f" * 32).status_code == 404
    assert tc.get("/api/accounts").json()["accounts"] == []


def test_sign_in_again_must_be_the_same_person(google):
    _, tc, fake, opened = google
    acct = sign_in(tc, fake, opened)["account"]
    fake.sub = "100000000000000000999"
    st = sign_in(tc, fake, opened, account=acct["id"])
    assert st["state"] == "error" and acct["label"] in st["error"]
    fake.sub = "100000000000000000001"
    st = sign_in(tc, fake, opened, account=acct["id"])
    assert st["state"] == "done" and st["account"]["id"] == acct["id"]
    r = tc.post(
        "/api/accounts/connect", json={"kind": "gdrive", "account": "f" * 32}, headers=ORIGIN
    )
    assert r.status_code == 404


def test_connect_a_drive_folder(google, monkeypatch):
    from anagram.local.sources.gdrive import GDOC, GoogleDriveConnector

    monkeypatch.setattr(GoogleDriveConnector, "rate", 1e9)
    svc, tc, fake, opened = google
    kinds = {k["kind"]: k for k in tc.get("/api/source-kinds").json()["kinds"]}
    assert kinds["gdrive"]["available"] and kinds["gdrive"]["choose"] == "folders"
    lab = fake.add_folder("Lab")
    fake.add_file("Plan", b"# Plan\n\nNanodiscs.", parent=lab, mime=GDOC)
    acct = sign_in(tc, fake, opened)["account"]["id"]
    top = tc.get(f"/api/accounts/{acct}/choices", params={"kind": "gdrive"}).json()["items"]
    assert top[0]["type"] == "my_drive"
    folders = tc.get(
        f"/api/accounts/{acct}/choices", params={"kind": "gdrive", "parent": "my_drive"}
    ).json()["items"]
    assert [(f["id"], f["name"]) for f in folders] == [(lab, "Lab")]
    body = {"account": acct, "include": {"folders": [lab]}, "kind": "gdrive"}
    assert tc.post("/api/sources/preview", json=body, headers=ORIGIN).json() == {
        "estimate": None,
        "of": None,
    }
    out = add(tc, **body)
    sid = out["sources"][0]
    r = row(tc, sid)
    assert r["account"] == {"id": acct, "label": fake.email}
    assert r["items"] == 1 and r["kind"] == "gdrive"
    assert r["label"] == f"Google Drive ({fake.email})"
    assert r["include"] == {"folders": [lab], "my_drive": False, "shared_drives": []}
    assert tc.get("/api/accounts").json()["accounts"][0]["sources"] == [sid]
    # The same account and kind is not added a second time.
    assert add(tc, **body)["added"] == 0
    bad = tc.post("/api/sources", json={**body, "include": {}}, headers=ORIGIN)
    assert bad.status_code == 400 and bad.json()["code"] == "bad_include"
    # Removal of the last source of the account revokes the grant.
    r = tc.request("DELETE", f"/api/sources/{sid}", json={"delete_data": True}, headers=ORIGIN)
    assert r.json()["account_revoked"] is True
    assert tc.get("/api/accounts").json()["accounts"] == []
    assert svc.keystore().list("acct-") == []


def test_cloud_source_needs_the_scope(google):
    _, tc, fake, opened = google
    acct = sign_in(tc, fake, opened)["account"]["id"]
    # A Gmail grant is not a Drive grant: the person signs in again for it.
    with_svc = {"account": acct, "include": {"my_drive": True}, "kind": "gdrive"}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("anagram.local.sources.oauth.KIND_SCOPES", {"gdrive": ("google", ("x-scope",))})
        mp.setattr("anagram.shell.ui.sources.KIND_SCOPES", {"gdrive": ("google", ("x-scope",))})
        r = tc.post("/api/sources", json=with_svc, headers=ORIGIN)
    assert r.status_code == 409 and r.json()["code"] == "scope_missing"
    r = tc.post("/api/sources", json={**with_svc, "account": "f" * 32}, headers=ORIGIN)
    assert r.status_code == 404


def test_connect_gmail_stays_private(google, monkeypatch):
    from anagram.local.sources.gmail import GmailConnector

    monkeypatch.setattr(GmailConnector, "rate", 1e9)
    _, tc, fake, opened = google
    kinds = {k["kind"]: k for k in tc.get("/api/source-kinds").json()["kinds"]}
    assert kinds["gmail"]["spaces"] == ["private"] and kinds["gmail"]["choose"] == "filter"
    fake.gmail.add_message("Plan", "The plan.", sent=True)
    acct = sign_in(tc, fake, opened, kind="gmail")["account"]["id"]
    out = tc.get(f"/api/accounts/{acct}/choices", params={"kind": "gmail"}).json()
    assert out["email"] == fake.email and out["total"] == 1
    body = {"account": acct, "filter": {"mode": "mine"}, "kind": "gmail"}
    assert tc.post("/api/sources/preview", json=body, headers=ORIGIN).json() == {
        "estimate": 1,
        "of": 1,
    }
    bad = tc.post("/api/sources", json={**body, "space": "lab:x"}, headers=ORIGIN)
    assert bad.status_code == 400
    sid = add(tc, **body)["sources"][0]
    r = row(tc, sid)
    assert r["kind"] == "gmail" and r["items"] == 1
    r = tc.patch(f"/api/sources/{sid}", json={"space": "lab:x"}, headers=ORIGIN)
    assert r.status_code == 400 and r.json()["code"] == "space_refused"
    r = tc.patch(f"/api/sources/{sid}", json={"filter": {"mode": "x"}}, headers=ORIGIN)
    assert r.status_code == 400


def test_zotero_web_with_a_pasted_key(member, monkeypatch):
    from anagram.local.sources import zotero as zotero_mod
    from anagram.local.sources.zotero import FakeZotero
    from anagram.shell.ui import connections

    svc, tc = member
    fake = FakeZotero(
        user_id="4242",
        api_key="Fk9zZotero0Key0Abc123",
        items=[{"id": "p1", "title": "Nanodisc assembly", "type": "article-journal"}],
    )
    monkeypatch.setattr(zotero_mod, "urllib_transport", lambda timeout=30: fake)
    monkeypatch.setattr(connections, "zotero_transport", lambda timeout=30: fake)
    kinds = {k["kind"]: k for k in tc.get("/api/source-kinds").json()["kinds"]}
    assert kinds["zotero_web"]["auth"] == "api_key" and kinds["zotero_web"]["available"]
    assert "github" not in kinds
    bad = tc.post(
        "/api/accounts/key", json={"key": "Wrong0Key0000000", "kind": "zotero_web"}, headers=ORIGIN
    )
    assert bad.status_code == 400 and bad.json()["error"] == "This key does not work."
    bad = tc.post("/api/accounts/key", json={"key": "x", "kind": "zotero_web"}, headers=ORIGIN)
    assert bad.status_code == 400
    bad = tc.post("/api/accounts/key", json={"key": fake.api_key, "kind": "gdrive"}, headers=ORIGIN)
    assert bad.status_code == 400
    r = tc.post(
        "/api/accounts/key", json={"key": fake.api_key, "kind": "zotero_web"}, headers=ORIGIN
    )
    assert r.status_code == 200, r.text
    acct = r.json()["account"]
    assert acct["label"] == "member" and fake.api_key not in r.text
    sid = add(tc, kind="zotero_web", account=acct["id"])["sources"][0]
    cfg_row = row(tc, sid)
    assert cfg_row["items"] == 1 and cfg_row["kind"] == "zotero_web"
    assert fake.api_key not in json.dumps(cfg_row)
    # The key is in the keystore only, as the token of the account.
    assert svc.keystore().get("acct-" + acct["id"]) is not None
    assert fake.api_key.encode() not in (svc.home / "index.sqlite").read_bytes()


def test_zotero_web_old_config_reads_the_keystore_entry():
    from anagram.local.sources import connector_from_config
    from anagram.local.sources.zotero import FakeZotero

    fake = FakeZotero(api_key="OldKey0000000000")
    conn = connector_from_config(
        {"kind": "zotero_web", "user_id": "1"},
        secret=lambda name: {"zotero-api-key": fake.api_key}[name],
        transport=fake,
    )
    assert conn.config() == {"kind": "zotero_web", "user_id": "1"}
    assert conn.fetch() == []


def test_browse_detects_obsidian_and_git(tmp_path):
    from anagram.shell.ui.sources import SourcesUI

    vault = tmp_path / "vault"
    (vault / ".obsidian").mkdir(parents=True)
    got = SourcesUI.browse(str(vault))
    assert got["is_obsidian"] is True and got["is_git"] is False
    (vault / ".git").mkdir()
    got2 = SourcesUI.browse(str(vault))
    assert got2["is_obsidian"] is True and got2["is_git"] is True
