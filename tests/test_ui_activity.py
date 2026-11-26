"""`GET /api/activity` (plan R7 step 9b): the Home lines from the bus."""

from __future__ import annotations

from anagram.shell.ui.events import EventBus
from anagram.shell.ui.routers.activity import Activity


def test_activity_keeps_known_events_newest_first_and_joins_a_run():
    clock = [1_800_000_000.0]
    bus = EventBus(clock=lambda: clock[0])
    act = Activity()
    bus.tap(act.add)
    bus.publish("source.progress", {"id": "s1", "done": 1, "total": 2})  # not a line
    bus.publish("source.added", {"source": {"id": "s1", "label": "/Users/x/Lab notes"}})
    clock[0] += 5
    bus.publish("suggestion.new", {"id": "p1", "title": "Three states of NbT7", "state": "new"})
    clock[0] += 5
    bus.publish("suggestion.new", {"id": "p2", "title": "G14 movies", "state": "new"})
    clock[0] += 5
    bus.publish("shared.received", {"grant_id": "g", "sender": "Maya Lind", "title": "x"})
    lines = act.lines()
    assert [x["type"] for x in lines] == ["shared.received", "suggestion.new", "source.added"]
    assert lines[0]["screen"] == "sharing" and lines[0]["params"]["n"] == 1
    assert lines[1]["params"] == {"title": "G14 movies", "n": 2}
    # No path: only the last part of the place.
    assert lines[2]["params"] == {"name": "Lab notes", "n": 1}
    assert act.lines(since=lines[1]["at"]) == [lines[0]]


def test_a_read_line_names_the_reader_and_opens_shared_by_me():
    bus = EventBus()
    act = Activity()
    bus.tap(act.add)
    bus.publish("share.read", {"finding_id": "f1", "reader": "Chidi Okafor", "subject": "u_1"})
    (line,) = act.lines()
    assert line["screen"] == "sharing" and line["route"] == {"tab": "by-me"}
    assert line["params"] == {"name": "Chidi Okafor", "n": 1}


def test_a_run_ends_after_the_join_time():
    clock = [1_800_000_000.0]
    bus = EventBus(clock=lambda: clock[0])
    act = Activity()
    bus.tap(act.add)
    bus.publish("suggestion.new", {"id": "a", "title": "A", "state": "new"})
    clock[0] += 3600
    bus.publish("suggestion.new", {"id": "b", "title": "B", "state": "new"})
    assert [x["params"]["n"] for x in act.lines()] == [1, 1]


def test_a_tap_that_fails_does_not_stop_the_publisher():
    bus = EventBus()
    seen = []

    def broken(event):
        raise RuntimeError("no")

    bus.tap(broken)
    bus.tap(seen.append)
    bus.publish("source.added", {"source": {"id": "s1", "label": "x"}})
    assert [e.type for e in seen] == ["source.added"]


def test_activity_route_needs_the_cookie_and_gives_lines(tmp_path):
    from fastapi.testclient import TestClient

    from anagram.shell.ui.server import create_ui_app
    from anagram.shell.ui.service import UIService

    app = create_ui_app(UIService(tmp_path / "home"), port=8123, token="t")  # noqa: S106
    tc = TestClient(app, base_url="http://127.0.0.1:8123")
    assert tc.get("/api/activity").status_code == 401
    tc.get("/open/t", follow_redirects=False)
    app.state.ctx.bus.publish(
        "shared.received", {"grant_id": "g", "sender": "Maya Lind", "title": "x"}
    )
    rows = tc.get("/api/activity").json()
    assert rows[0]["text_key"] == "act_shared" and rows[0]["params"]["sender"] == "Maya Lind"
