"""The item, kind, and suggestion routes of the local UI (R4 step 11).

The boundary, the space of each item (`spaces.space_of`), the scope rule,
the kind correction of the person (it stays for a new version), and the
state of proposed findings with their events. Fake models only; no network.
"""

from __future__ import annotations

import pytest
from test_index_proposals import FOLLOW, GEL, OTHER, PROTOCOL, fake_reader
from test_ui_models_api import ORIGIN, UI

from anagram.local.index import spaces
from anagram.local.sources import FolderConnector, source_state
from anagram.local.understanding import proposals, understand
from anagram.models.providers.fake import FakeTextModel
from anagram.shell.ui import understanding as understanding_ui

pytestmark = pytest.mark.usefixtures("no_network")

LAB = "lab:lab-0123456789abcdef"
ROUTES = (
    ("GET", "/api/kinds"),
    ("GET", "/api/items"),
    ("GET", "/api/items/item:1"),
    ("PUT", "/api/items/item:1/kind"),
    ("GET", "/api/suggestions"),
    ("POST", "/api/suggestions/some-id"),
)
FILES = {
    "alpha/gel.md": GEL,
    "alpha/protocol.md": PROTOCOL,
    "beta/followup.md": FOLLOW,
    "gamma/mice.md": OTHER,
}


def fill(ui: UI, tmp_path, files=FILES, name: str = "lab") -> tuple[str, object]:
    """A folder source with `files`, scanned and read by the fake model. The
    label is the name that the sources screen gives (`default_label`)."""
    root = tmp_path / name
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    with ui.svc.session(index=True) as (_, idx):
        sid = idx.add_source(FolderConnector(root), label=name)
        idx.scan()
        report = understand.run(idx, FakeTextModel(fake_reader), limit=50)
        assert report.failed == 0
    return sid, root


def by_title(items: list[dict]) -> dict[str, dict]:
    return {i["title"]: i for i in items}


def events(ui: UI, topic: str) -> list[dict]:
    return [d for t, d in ui.bus.seen if t == topic]


@pytest.fixture
def ui(tmp_path):
    return UI(tmp_path).launch()


# ----------------------------------------------------------------- boundary


def test_item_routes_obey_the_local_ui_boundary(tmp_path):
    ui = UI(tmp_path)
    paths = {
        (m, r.path.replace("{ref}", "item:1").replace("{draft_id}", "some-id"))
        for r in ui.app.routes
        for m in getattr(r, "methods", None) or ()
        if r.path.startswith(("/api/kinds", "/api/items", "/api/suggestions"))
    }
    assert paths == set(ROUTES)
    for method, path in ROUTES:
        assert ui.tc.request(method, path, json={}, headers=ORIGIN).status_code == 401, path
    ui.launch()
    for method, path in ROUTES:
        evil = ui.tc.request(method, path, json={}, headers={"Origin": "http://evil.example"})
        assert evil.status_code == 403, path
        cross = ui.tc.request(
            method, path, json={}, headers={**ORIGIN, "Sec-Fetch-Site": "cross-site"}
        )
        assert cross.status_code == 403, path
        rebind = ui.tc.request(method, path, json={}, headers={**ORIGIN, "Host": "evil.example"})
        assert rebind.status_code == 421, path
        if method != "GET":
            assert ui.tc.request(method, path, json={}).status_code == 403, path
    assert ui.bus.seen == []


def test_item_routes_need_a_joined_home(tmp_path):
    ui = UI(tmp_path, joined=False).launch()
    assert "Join" in ui.call("GET", "/api/items", status=409)["error"]
    assert "Join" in ui.call("GET", "/api/suggestions", status=409)["error"]


# -------------------------------------------------------------------- items


def test_items_have_kind_title_and_the_space_of_their_source(ui, tmp_path):
    sid, _ = fill(ui, tmp_path)
    got = ui.call("GET", "/api/items")
    assert got["next"] is None and len(got["items"]) == 4
    with ui.svc.session(index=True) as (_, idx):
        space = spaces.space_of(idx, sid)
    for row in got["items"]:
        assert set(row) == {
            "by",
            "confidence",
            "kind",
            "polarity",
            "ref",
            "source_label",
            "space",
            "summary",
            "time",
            "title",
        }
        assert row["space"] == space == "private" and row["by"] == "model"
        assert row["ref"].startswith("item:") and "/" not in row["title"]
        assert row["source_label"] == "lab"
    rows = by_title(got["items"])
    assert rows["Band shift of NbT7 with LX-4"]["kind"] == "finding"
    assert rows["Gel protocol for NbT7"]["kind"] == "method"

    counts = {k["id"]: k for k in ui.call("GET", "/api/kinds")}
    assert list(counts)[0] == "finding" and len(counts) == 13
    assert counts["finding"] == {"count": 3, "id": "finding", "label": "Finding"}
    assert counts["method"]["count"] == 1 and counts["correspondence"]["label"] == "Message"

    only = ui.call("GET", "/api/items?kind=method")["items"]
    assert [i["title"] for i in only] == ["Gel protocol for NbT7"]
    found = ui.call("GET", "/api/items?q=mouse")["items"]
    assert [i["title"] for i in found] == ["Mouse colonies"]
    assert ui.call("GET", "/api/items?space=private")["items"] == got["items"]

    # Pages: the cursor gives the rest, with no item two times.
    first = ui.call("GET", "/api/items?limit=3")
    rest = ui.call("GET", f"/api/items?limit=3&cursor={first['next']}")
    assert rest["next"] is None
    assert [i["ref"] for i in first["items"] + rest["items"]] == [i["ref"] for i in got["items"]]

    for bad in (
        "kind=pdf",
        "limit=0",
        "limit=201",
        "limit=many",
        "cursor=%21%21",
        "q=" + "a" * 201,
    ):
        assert ui.call("GET", f"/api/items?{bad}", status=400)["error"]
    assert ui.call("GET", "/api/kinds?space=elsewhere", status=400)["error"]


def test_a_space_outside_the_readable_scope_gives_nothing(ui, tmp_path, monkeypatch):
    fill(ui, tmp_path)
    lab_sid, _ = fill(
        ui, tmp_path, {"shared/plan.md": "# Grant aims\n\nAims for next year.\n"}, "l"
    )
    with ui.svc.session(index=True) as (_, idx):
        source_state.set_space(idx.store, lab_sid, LAB, now=0)
        (lab_ref,) = [
            f"item:{r[0]}"
            for r in idx.store.q("SELECT id FROM item WHERE source_id = ?", (lab_sid,))
        ]

    # Before the lab key exists (R2 S4), the lab is not readable here.
    refs = [i["ref"] for i in ui.call("GET", "/api/items")["items"]]
    assert lab_ref not in refs and len(refs) == 4
    assert ui.call("GET", f"/api/items?space={LAB}", status=400)["error"]
    assert ui.call("GET", f"/api/items/{lab_ref}", status=404)["error"]
    assert ui.call("PUT", f"/api/items/{lab_ref}/kind", {"kind": "note"}, status=404)

    # With the lab key, each scope gives only its own items.
    readable = lambda labs: frozenset({"private", LAB})  # noqa: E731
    monkeypatch.setattr(spaces, "readable_spaces", readable)
    monkeypatch.setattr(understanding_ui, "readable_spaces", readable)
    lab_only = ui.call("GET", f"/api/items?space={LAB}")["items"]
    assert [(i["ref"], i["space"]) for i in lab_only] == [(lab_ref, LAB)]
    private = ui.call("GET", "/api/items?space=private")["items"]
    assert lab_ref not in [i["ref"] for i in private] and len(private) == 4
    assert len(ui.call("GET", "/api/items?space=all")["items"]) == 5
    assert ui.call("GET", f"/api/items/{lab_ref}")["space"] == LAB


def test_one_item_with_claims_names_links_and_versions(ui, tmp_path):
    fill(ui, tmp_path)
    ui.call("GET", "/api/suggestions")  # makes the links
    rows = by_title(ui.call("GET", "/api/items")["items"])
    gel = rows["Band shift of NbT7 with LX-4"]
    got = ui.call("GET", f"/api/items/{gel['ref']}")
    assert got["kind"] == "finding" and got["space"] == "private"
    assert got["claims"][0]["text"].startswith("We found that NbT7 binds LX-4")
    assert got["claims"][0]["status"] == "observed"
    assert {"text": "nbt7", "type": "material"} in got["entities"]
    assert got["people"] == []
    (version,) = got["versions"]
    assert set(version) == {"at", "n"}
    related = {(link["relation"], link["title"]) for link in got["links"]}
    assert ("related", "NbT7 and LX-4 again") in related
    assert ("supported_by", "Gel protocol for NbT7") in related
    protocol = ui.call("GET", f"/api/items/{rows['Gel protocol for NbT7']['ref']}")
    assert ("supports", "Band shift of NbT7 with LX-4") in {
        (link["relation"], link["title"]) for link in protocol["links"]
    }
    for ref in ("item:999999", "file:1", "item:abc", "item:"):
        assert ui.call("GET", f"/api/items/{ref}", status=404)["error"]


def test_a_correction_wins_and_survives_a_new_version(ui, tmp_path):
    sid, root = fill(ui, tmp_path)
    rows = by_title(ui.call("GET", "/api/items")["items"])
    mice = rows["Mouse colonies"]
    assert mice["kind"] == "finding"
    got = ui.call("PUT", f"/api/items/{mice['ref']}/kind", {"kind": "note"})
    assert (got["kind"], got["by"], got["confidence"]) == ("note", "person", 1.0)
    (event,) = events(ui, "item.kind")
    assert event == {
        "by": "person",
        "confidence": 1.0,
        "kind": "note",
        "ref": mice["ref"],
        "title": "Mouse colonies",
    }

    # A new version of the file, read again by the model: the kind stays.
    (root / "gamma/mice.md").write_text(OTHER + "\nWe found the same in a second run.\n")
    with ui.svc.session(index=True) as (_, idx):
        idx.scan()
        understand.run(idx, FakeTextModel(fake_reader), limit=50)
    again = ui.call("GET", f"/api/items/{mice['ref']}")
    assert len(again["versions"]) == 2
    assert (again["kind"], again["by"]) == ("note", "person")

    assert ui.call("PUT", f"/api/items/{mice['ref']}/kind", {"kind": "pdf"}, status=400)
    assert ui.call("PUT", f"/api/items/{mice['ref']}/kind", {}, status=400)
    assert ui.call("PUT", "/api/items/item:999999/kind", {"kind": "note"}, status=404)
    assert len(events(ui, "item.kind")) == 1


# -------------------------------------------------------------- suggestions


def test_suggestions_later_and_not_a_finding(ui, tmp_path):
    fill(ui, tmp_path)
    first = ui.call("GET", "/api/suggestions")
    assert len(first) == 2 and {s["state"] for s in first} == {"new"}
    for s in first:
        assert s["reason"] and s["title"] and "/" not in s["title"]
        assert {"claim_suggestion", "items", "third_party", "topics", "id"} <= set(s)
    news = events(ui, "suggestion.new")
    assert sorted(e["id"] for e in news) == sorted(s["id"] for s in first)
    ui.call("GET", "/api/suggestions")
    assert len(events(ui, "suggestion.new")) == 2  # one time for each proposal

    nbt7 = next(s for s in first if len(s["items"]) == 2)  # the protocol is a link, not evidence
    mice = next(s for s in first if len(s["items"]) == 1)
    after = ui.call("POST", f"/api/suggestions/{nbt7['id']}", {"action": "later"})
    assert [(s["id"], s["state"]) for s in after] == [(mice["id"], "new"), (nbt7["id"], "later")]
    assert events(ui, "suggestion.changed")[-1] == {
        "id": nbt7["id"],
        "state": "later",
        "title": nbt7["title"],
    }

    after = ui.call("POST", f"/api/suggestions/{mice['id']}", {"action": "dismiss"})
    assert [s["id"] for s in after] == [nbt7["id"]]
    assert events(ui, "suggestion.changed")[-1]["state"] == "dismissed"
    (kind_event,) = events(ui, "item.kind")
    assert (kind_event["kind"], kind_event["by"]) == ("note", "person")
    rows = by_title(ui.call("GET", "/api/items")["items"])
    assert rows["Mouse colonies"]["kind"] == "note"
    assert [s["id"] for s in ui.call("GET", "/api/suggestions")] == [nbt7["id"]]

    assert ui.call("POST", f"/api/suggestions/{mice['id']}", {"action": "later"}, status=404)
    assert ui.call("POST", f"/api/suggestions/{nbt7['id']}", {"action": "stamp"}, status=400)


def test_used_drafts_of_the_old_ui_state_become_stamped(ui, tmp_path):
    fill(ui, tmp_path)
    first = ui.call("GET", "/api/suggestions")
    gone = first[0]["id"]
    # A home from before R6 X2: the list is in the UI state, not copied yet.
    ui.svc.state.update(used_drafts=[gone, "0123456789abcdef"], used_drafts_imported=False)
    after = ui.call("GET", "/api/suggestions")
    assert gone not in [s["id"] for s in after] and len(after) == len(first) - 1
    with ui.svc.session(index=True) as (_, idx):
        states = proposals.states(idx)
    assert states[gone] == "stamped" and states["0123456789abcdef"] == "stamped"
    changed = events(ui, "suggestion.changed")
    assert changed == [{"id": gone, "state": "stamped", "title": None}]
    ui.call("GET", "/api/suggestions")
    assert len(events(ui, "suggestion.changed")) == 1  # copied one time
    # The old route reads the same state.
    assert gone not in [d["id"] for d in ui.call("GET", "/api/drafts")]
    # After the copy, a new ID in the old list is not read again (R6 X2).
    ui.svc.state.update(used_drafts=[first[1]["id"]])
    assert first[1]["id"] in [s["id"] for s in ui.call("GET", "/api/suggestions")]


def test_a_negative_result_shows_on_the_item_proposal_and_finding(ui, tmp_path):
    """Decision C12: the routes give the polarity; a negative finding is
    proposed and stamped as each other finding is."""
    null = (
        "# Ligand LX-4 and the band\n\n"
        "We found that adding LX-4 does not change the band of NbT7 in 40 runs.\n"
        "Ben Okoye repeated the full series and saw the same. We drop LX-4 as a cause.\n"
    )

    def reader(request):
        out = fake_reader(request)
        if out.get("kind") in ("finding", "result"):
            out["polarity"] = "negative" if "does not change" in request.user else "positive"
        return out

    root = tmp_path / "neg"
    (root / "a").mkdir(parents=True)
    (root / "a" / "null.md").write_text(null)
    with ui.svc.session(index=True) as (_, idx):
        idx.add_source(FolderConnector(root), label="neg")
        idx.scan()
        assert understand.run(idx, FakeTextModel(reader), limit=50).failed == 0
    item = by_title(ui.call("GET", "/api/items")["items"])["Ligand LX-4 and the band"]
    assert item["kind"] == "finding" and item["polarity"] == "negative"
    assert ui.call("GET", f"/api/items/{item['ref']}")["polarity"] == "negative"
    [draft] = ui.call("GET", "/api/suggestions")
    assert draft["polarity"] == "negative"
    finding = ui.call("POST", "/api/findings", {"draft_id": draft["id"], "claim": "No change."})
    assert finding["polarity"] == "negative"
    assert ui.call("GET", "/api/findings")[0]["polarity"] == "negative"


def test_a_stamped_finding_leaves_the_suggestions(ui, tmp_path):
    """R6 X2: the finding route marks the proposal `stamped`."""
    fill(ui, tmp_path)
    first = ui.call("GET", "/api/suggestions")
    target = first[0]
    ui.call("POST", "/api/findings", {"draft_id": target["id"], "claim": "A test claim."})
    with ui.svc.session(index=True) as (_, idx):
        assert proposals.states(idx)[target["id"]] == "stamped"
    assert target["id"] not in [s["id"] for s in ui.call("GET", "/api/suggestions")]
