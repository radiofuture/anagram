"""The search and ask routes of the local UI (R4 step 15, the part that Home
needs): the boundary, the scope, and the `ask.*` events in order on the one
stream with the thread id as their key. Fake models only; no network."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from test_index_proposals import GEL, OTHER
from test_ui_items_api import fill
from test_ui_models_api import ORIGIN, UI

from anagram.local.sources import source_state
from anagram.models import ModelError
from anagram.models.providers.fake import FakeTextModel

pytestmark = pytest.mark.usefixtures("no_network")

LAB = "lab:lab-0123456789abcdef"
ROUTES = (
    ("GET", "/api/search"),
    ("GET", "/api/ask/setup"),
    ("POST", "/api/ask"),
    ("GET", "/api/ask/history"),
    ("DELETE", "/api/ask/history"),
    ("GET", "/api/ask/some-thread"),
    ("GET", "/api/timeline"),
)
FILES = {"alpha/gel.md": GEL, "gamma/mice.md": OTHER}


@pytest.fixture
def ui(tmp_path):
    ui = UI(tmp_path).launch()
    keys: list[tuple[str, str | None]] = []
    publish = ui.bus.publish

    def keyed(type_, data=None, *, key=None):
        keys.append((type_, key))
        return publish(type_, data, key=key)

    ui.bus.publish = keyed
    ui.keys = keys
    return ui


def ask_events(ui) -> list[tuple[str, dict]]:
    return [(t, d) for t, d in ui.bus.seen if t.startswith("ask.")]


def use_model(ui, model) -> None:
    ui.models.ask_model = lambda client, cfg: (model, None)


def test_routes_obey_the_local_ui_boundary(tmp_path):
    ui = UI(tmp_path)
    for method, path in ROUTES:
        assert ui.tc.request(method, path, json={}, headers=ORIGIN).status_code == 401, path
    ui.launch()
    for method, path in ROUTES:
        evil = ui.tc.request(method, path, json={}, headers={"Origin": "http://evil.example"})
        assert evil.status_code == 403, path
        rebind = ui.tc.request(method, path, json={}, headers={**ORIGIN, "Host": "evil.example"})
        assert rebind.status_code == 421, path
        if method != "GET":
            assert ui.tc.request(method, path, json={}).status_code == 403, path


def test_search_is_scoped(ui, tmp_path):
    fill(ui, tmp_path, FILES)
    got = ui.call("GET", "/api/search?q=NbT7")
    assert got["mode"] == "text" and got["hits"]
    hit = got["hits"][0]
    assert hit["title"] == "Band shift of NbT7 with LX-4" and hit["space"] == "private"
    assert ui.call("GET", f"/api/search?q=NbT7&space={LAB}", status=400)["error"]
    assert ui.call("GET", "/api/search?q=NbT7&kind=poem", status=400)["error"]
    assert ui.call("GET", "/api/search?q=NbT7&k=500", status=400)["error"]
    assert ui.call("GET", "/api/search?q=")["hits"] == []


def test_ask_events_arrive_in_order_with_the_thread_as_key(ui, tmp_path):
    fill(ui, tmp_path, FILES)
    use_model(ui, FakeTextModel(["NbT7 binds LX-4 at pH 6 [1]. The band moved [1][4]."], pieces=6))
    ui.svc.ask.delta_s = 0  # each piece is one event in this test
    thread = ui.call("POST", "/api/ask", {"question": "What does NbT7 bind?"})["thread"]

    end = time.monotonic() + 10
    while not any(t in ("ask.done", "ask.error") for t, _ in ask_events(ui)):
        assert time.monotonic() < end, ask_events(ui)
        time.sleep(0.02)
    got = ask_events(ui)
    types = [t for t, _ in got]
    assert types[0] == "ask.sources" and types[-1] == "ask.done"
    assert set(types[1:-1]) == {"ask.delta"} and len(types) > 3
    assert all(d["thread"] == thread for _, d in got)
    assert all(k == thread for t, k in ui.keys if t.startswith("ask."))
    done = got[-1][1]
    assert done["mode"] == "answer" and done["citations"] == [1] and "[4]" not in done["text"]
    assert "".join(d["text"] for t, d in got if t == "ask.delta").startswith("NbT7 binds")
    again = ui.call("GET", f"/api/ask/{thread}")
    assert again["state"] == "done" and again["answer"] == done["text"]
    assert again["sources"] and again["question"] == "What does NbT7 bind?"
    history = ui.call("GET", "/api/ask/history")
    assert [h["question"] for h in history] == ["What does NbT7 bind?"]
    assert ui.call("DELETE", "/api/ask/history") == {"cleared": 1}
    assert ui.call("GET", "/api/ask/history") == []


def test_with_no_model_the_passages_are_the_answer(ui, tmp_path):
    fill(ui, tmp_path, FILES)
    setup = ui.call("GET", "/api/ask/setup")
    assert setup["model"] is None and setup["state"]["state"] == "no_model"
    assert setup["spaces"] == [{"id": "private", "label": None}]
    assert sorted(setup["examples"]) == ["Band shift of NbT7 with LX-4", "Mouse colonies"]
    thread = ui.svc.ask.start_ask("NbT7 gel", None, wait=True)["thread"]
    got = ask_events(ui)
    assert [t for t, _ in got] == ["ask.sources", "ask.done"]
    assert got[1][1]["mode"] == "passages" and got[1][1]["reason"] == "no_model"
    assert ui.call("GET", f"/api/ask/{thread}")["mode"] == "passages"


def test_a_model_fault_gives_one_sentence(ui, tmp_path):
    fill(ui, tmp_path, FILES)
    use_model(ui, FakeTextModel([ModelError("unreachable", retryable=True)]))
    ui.svc.ask.start_ask("NbT7", None, wait=True)
    got = ask_events(ui)
    assert [t for t, _ in got] == ["ask.sources", "ask.error"]
    assert got[1][1]["message"] == "Anagram cannot reach the model."


def test_a_lab_scope_never_gives_private_passages(ui, tmp_path):
    sid, _ = fill(ui, tmp_path, FILES)
    with ui.svc.session(index=True) as (_, idx):
        source_state.set_space(idx.store, sid, LAB, now=1.0)
    # The lab is not readable on this computer: the scope is refused.
    assert ui.call("POST", "/api/ask", {"question": "NbT7", "space": LAB}, status=400)["error"]
    ui.svc.ask.start_ask("NbT7", "private", wait=True)
    got = ask_events(ui)
    assert got[0][1]["sources"] == []


@pytest.mark.parametrize("question", ["", "   ", "x" * 501, None, 7])
def test_a_bad_question_is_refused(ui, question):
    assert ui.call("POST", "/api/ask", {"question": question}, status=400)["error"]


# ----------------------------------------------------------------- timeline


def _wait(ui, topic: str) -> None:
    end = time.monotonic() + 10
    while not any(t == topic for t, _ in ui.bus.seen):
        assert time.monotonic() < end, ui.bus.seen
        time.sleep(0.02)


def real_today(ui) -> None:
    """The files of `fill` have the time of now, so the range of the
    timeline must end after the UTC day of now, not a fixed day."""
    ui.models.today = lambda: datetime.now(UTC).date()


def test_the_timeline_route_gives_weeks_with_no_model(ui, tmp_path):
    real_today(ui)
    fill(ui, tmp_path, FILES)
    weeks = ui.call("GET", "/api/timeline")
    assert weeks and all(
        set(w) >= {"week", "start", "findings", "results", "counts"} for w in weeks
    )
    assert all(w["summary"] is None and w["pending"] is False for w in weeks)
    titles = {r["title"] for w in weeks for n in ("findings", "results") for r in w[n]}
    assert "Band shift of NbT7 with LX-4" in titles
    assert ui.call("GET", f"/api/timeline?space={LAB}", status=400)["error"]
    assert ui.call("GET", "/api/timeline?since=yesterday", status=400)["error"]
    assert ui.call("GET", "/api/timeline?since=2026-11-10&until=2026-11-01", status=400)["error"]
    assert ui.call("GET", "/api/timeline?since=2020-01-01&until=2026-01-01", status=400)["error"]


def test_a_missing_summary_is_made_on_a_worker(ui, tmp_path):
    real_today(ui)
    fill(ui, tmp_path, FILES)
    model = FakeTextModel(["NbT7 binds LX-4 [1]."])
    use_model(ui, model)
    first = ui.call("GET", "/api/timeline")
    assert any(w["pending"] for w in first) and all(w["summary"] is None for w in first)
    _wait(ui, "timeline.changed")
    calls = len(model.calls)
    assert calls >= 1 and all(c.purpose == "digest" for c in model.calls)
    again = ui.call("GET", "/api/timeline")
    done = [w for w in again if w["summary"]]
    assert done and done[0]["citations"][0]["n"] == 1
    assert not any(w["pending"] for w in again)
    assert len(model.calls) == calls  # the cache answers
