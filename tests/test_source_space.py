# ruff: noqa: F811 - the fixtures come from test_ui_sources_api
"""Space assignment with the R2 lab policy, lab OAuth clients from the lab
settings record (plan R3 step S12), and source labels (carry-over X3). The
node is the in-process fake of conftest. No network."""

from __future__ import annotations

import json

import pytest
from sourcekit import loopback_only  # noqa: F401 - fixture
from test_ui_api import ORIGIN
from test_ui_sources_api import (  # noqa: F401 - fixtures
    add,
    events,
    google,
    member,
    places,
    row,
    sign_in,
)

from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector, source_labels
from anagram.local.sources import source_state as ss
from anagram.local.sources.oauth import client_resolver
from anagram.shell.ui.errors import UIError

REFUSED = "Your lab does not permit this source in the lab space."


@pytest.fixture
def hooks(monkeypatch):
    """The route gives the lab-space hook to `set_space`. Here that hook calls
    each function of this list in its place."""

    added: list = []

    def space_hook(client, idx):
        return lambda sid, old, new: [h(sid, old, new) for h in added]

    monkeypatch.setattr("anagram.shell.ui.sources.lab_space_hook", space_hook)
    return added


def make_lab(svc, name: str = "My Lab", **sections) -> str:
    with svc.session() as c:
        lab_id = c.labs.lab_create(name)["lab_id"]
        if sections:
            c.lab_space.lab_set_settings(lab_id, sections)
    return lab_id


def kinds(tc) -> dict[str, dict]:
    return {k["kind"]: k for k in tc.get("/api/source-kinds").json()["kinds"]}


# ----------------------------------------------------------------- spaces


def test_patch_space_stores_publishes_and_calls_the_hooks(member, places, hooks):
    svc, tc = member
    calls = []
    hooks.append(lambda sid, old, new: calls.append((sid, old, new)))
    lab_id = make_lab(svc)
    sid = add(tc, kind="folder", path=str(places["work"] / "notes"))["sources"][0]
    r = tc.patch(f"/api/sources/{sid}", json={"space": f"lab:{lab_id}"}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["space"] == f"lab:{lab_id}"
    assert calls == [(sid, "private", f"lab:{lab_id}")]
    with svc.session(index=True) as (_, idx):
        assert ss.read(idx.store, sid).space == f"lab:{lab_id}"
    spaces = [e["data"]["space"] for e in events(svc, "source.state") if e["data"]["id"] == sid]
    assert spaces[-1] == f"lab:{lab_id}"
    r = tc.patch(f"/api/sources/{sid}", json={"space": "private"}, headers=ORIGIN)
    assert r.json()["space"] == "private"
    assert calls[-1] == (sid, f"lab:{lab_id}", "private")


def test_the_space_hook_gets_the_lab_context_and_the_index(member, places, monkeypatch):
    """The lab-space hook publishes at once, so the route gives it the
    lab context and the index of the session (`labspace.space_hook`)."""
    from anagram.network.api import AppLabs

    svc, tc = member
    seen = []

    def space_hook(labs, idx):
        given = isinstance(labs, AppLabs) and isinstance(idx, LocalIndex)
        return lambda sid, old, new: seen.append(given)

    monkeypatch.setattr("anagram.shell.ui.sources.lab_space_hook", space_hook)
    lab_id = make_lab(svc)
    sid = add(tc, kind="folder", path=str(places["work"] / "notes"))["sources"][0]
    r = tc.patch(f"/api/sources/{sid}", json={"space": f"lab:{lab_id}"}, headers=ORIGIN)
    assert r.status_code == 200
    assert seen == [True]


def test_a_lab_with_no_policy_here_is_not_a_space(member, places):
    _, tc = member
    sid = add(tc, kind="folder", path=str(places["work"] / "notes"))["sources"][0]
    r = tc.patch(f"/api/sources/{sid}", json={"space": "lab:" + "a" * 32}, headers=ORIGIN)
    assert r.status_code == 409 and r.json()["code"] == "space_unavailable"
    assert row(tc, sid)["space"] == "private"


def test_kind_choices_follow_the_lab_policy(member, places):
    svc, tc = member
    assert kinds(tc)["folder"]["labs"] == [] and kinds(tc)["folder"]["default_space"] == "private"
    lab_id = make_lab(svc, sources={"allowed_kinds": ["obsidian"], "lab_default": "lab"})
    by = kinds(tc)
    # A permitted kind: the lab is a choice and the default of the setup.
    assert by["obsidian"]["labs"] == [{"name": "My Lab", "space": f"lab:{lab_id}"}]
    assert by["obsidian"]["default_space"] == f"lab:{lab_id}"
    assert by["obsidian"]["lab_refused"] is None
    # A refused kind: no lab choice, one sentence, and private by default.
    assert by["folder"]["labs"] == [] and by["folder"]["default_space"] == "private"
    assert by["folder"]["lab_refused"] == REFUSED
    # Gmail stays private, also when the lab default is the lab space.
    assert by["gmail"]["labs"] == [] and by["gmail"]["default_space"] == "private"
    assert by["gmail"]["lab_refused"] is None
    # A refused kind can still be added as private, never into the lab.
    with pytest.raises(UIError) as err:
        svc.sources.add(
            {"kind": "folder", "path": str(places["work"] / "notes"), "space": f"lab:{lab_id}"}
        )
    assert err.value.status == 403
    sid = add(tc, kind="folder", path=str(places["work"] / "notes"))["sources"][0]
    assert row(tc, sid)["space"] == "private"
    vault = svc.sources.add(
        {"kind": "obsidian", "path": str(places["vault"]), "space": f"lab:{lab_id}"},
        refresh=False,
    )["sources"][0]
    assert row(tc, vault)["space"] == f"lab:{lab_id}"


def test_gmail_refuses_a_lab_space(member):
    svc, _ = member
    lab_id = make_lab(svc)
    with svc.session() as c:
        with pytest.raises(UIError) as err:
            svc.sources._check_space(c, _info("gmail"), f"lab:{lab_id}")
    assert err.value.status == 400


def _info(kind: str):
    from anagram.shell.ui.source_kinds import KINDS

    return KINDS[kind]


# ---------------------------------------------------------- lab clients


def test_a_lab_google_client_is_used(google):
    svc, tc, fake, opened = google
    (svc.home / "oauth-clients.json").unlink()  # no developer client
    assert kinds(tc)["gdrive"]["available"] is False
    make_lab(
        svc,
        oauth_clients={
            "google": {"client_id": fake.client_id, "client_secret": fake.client_secret}
        },
    )
    with svc.session() as c:
        found = client_resolver(c.lab_context, c.home)("google")
    assert (found.client_id, found.origin) == (fake.client_id, "lab")
    assert client_resolver(None, svc.home)("google") is None
    assert kinds(tc)["gdrive"]["available"] is True
    st = sign_in(tc, fake, opened)
    assert st["state"] == "done" and st["account"]["label"] == fake.email
    # The secret of the lab client is in no answer.
    assert fake.client_secret not in json.dumps(tc.get("/api/source-kinds").json())


# ------------------------------------------------------------ labels (X3)


def test_a_new_source_has_a_label_with_no_path(tmp_path):
    notes = tmp_path / "Lab notes"
    notes.mkdir()
    idx = LocalIndex(tmp_path / "index.sqlite", bytes(32))
    sid = idx.add_source(FolderConnector(notes))
    assert idx.source(sid)["label"] == "Lab notes"
    cfg = {"account": "a" * 32, "include": {"my_drive": True}, "kind": "gdrive"}
    assert source_labels.source_label(cfg, "ana@lab.org") == "Google Drive (ana@lab.org)"
    assert source_labels.source_label({"kind": "orcid_works", "orcid": "x"}) == "My ORCID works"
    idx.close()


def test_old_labels_are_migrated(tmp_path):
    notes = tmp_path / "Lab notes"
    notes.mkdir()
    path = tmp_path / "index.sqlite"
    idx = LocalIndex(path, bytes(32))
    sid = idx.add_source(FolderConnector(notes), label=f"folder {notes}")
    kept = idx.add_source(FolderConnector(tmp_path), label="Grant 2026 / drafts")
    idx.store.x("UPDATE source SET label = ? WHERE id = ?", (f"folder {notes}", sid))
    idx.close()
    idx = LocalIndex(path, bytes(32))
    assert idx.source(sid)["label"] == "Lab notes"
    assert idx.source(kept)["label"] == "Grant 2026 / drafts"
    assert source_labels.migrate(idx.store) == 0  # safe to run again
    idx.close()


@pytest.mark.parametrize(
    ("label", "raw"),
    [
        ("/Users/ana/notes", True),
        ("folder /Users/ana/notes", True),
        ("git ~/code/x", True),
        ("zotero export C:\\Users\\ana\\lib.json", True),
        ("zotero web library 4242", True),
        ("", True),
        ("Lab notes", False),
        ("Grant 2026 / drafts", False),
        ("Google Drive (ana@lab.org)", False),
    ],
)
def test_raw_label_rule(label, raw):
    assert source_labels.is_raw(label) is raw


def test_no_route_or_event_gives_a_path_as_a_label(member, places):
    svc, tc = member
    notes = places["work"] / "notes"
    sid = add(tc, kind="folder", path=str(notes))["sources"][0]
    r = tc.patch(f"/api/sources/{sid}", json={"label": str(notes)}, headers=ORIGIN)
    assert r.status_code == 400 and r.json()["code"] == "bad_label"
    # A raw label in the store (a plug-in, or a row from before X3) is not shown.
    with svc.session(index=True) as (_, idx):
        idx.set_source_label(sid, f"folder {notes}")
    assert row(tc, sid)["label"] == "notes"
    assert all(s["label"] == "notes" for s in tc.get("/api/sources").json()["sources"])
    texts = json.dumps([e["data"] for e in events(svc)])
    assert str(notes) not in texts
