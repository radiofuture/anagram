"""The live event bus of the local UI, the stream route, and the bridges.

No network: the bus is in memory, the stream route runs in the TestClient,
and one test uses the loopback UI server to close a connection.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import threading
import time

import pytest
from conftest import make_net
from fastapi.testclient import TestClient
from test_ui_api import ORIGIN, join_via_ui, launched, setup_person, ui_client

from anagram.local.sources import source_state
from anagram.shell.ui import bridge
from anagram.shell.ui.bridge import JoinBridge, Live, SourceEventBridge
from anagram.shell.ui.events import Closed, Event, EventBus, Publisher, frame
from anagram.shell.ui.routers import events as events_route
from anagram.shell.ui.server import UIServer, cookie_name, create_ui_app
from anagram.shell.ui.service import UIService

PORT = 41997
TOKEN = "launch-token-for-tests"  # noqa: S105 - a test value
BASE = f"http://127.0.0.1:{PORT}"


def drain(sub, limit: int = 1000) -> list[Event]:
    """All events that wait in a subscription."""

    async def run() -> list[Event]:
        out = []
        while len(out) < limit:
            event = await sub.next(0.01)
            if event is None:
                break
            out.append(event)
        return out

    return asyncio.run(run())


# ------------------------------------------------------------------- bus


def test_publish_gives_ids_in_order_and_the_topic_and_key():
    bus = EventBus(clock=lambda: 1_792_065_600)
    a = bus.publish("source.progress", {"id": "src_1", "done": 1, "total": 3})
    b = bus.publish("overview.changed")
    c = bus.publish("job.progress", {"done": 1}, key="job_9")
    assert [a.id, b.id, c.id] == [1, 2, 3]
    assert (a.type, a.topic, a.key) == ("source.progress", "source", "src_1")
    assert (b.topic, b.key, b.data) == ("overview", None, {})
    assert c.key == "job_9"
    assert a.at == "2026-10-15T12:00:00Z"
    assert bus.last_id == 3


def test_publish_refuses_a_bad_type_and_data_that_is_not_json():
    bus = EventBus()
    for bad in ("", "Source.progress", "source..x", ".x", "hello", "resync", 7):
        with pytest.raises(ValueError):
            bus.publish(bad)
    with pytest.raises(TypeError):
        bus.publish("source.progress", ["no"])
    with pytest.raises(TypeError):
        bus.publish("source.progress", {"path": object()})
    assert bus.last_id == 0


def test_a_subscriber_gets_hello_first_and_then_new_events():
    bus = EventBus()
    bus.publish("ring.changed")
    sub = bus.subscribe()
    assert bus.subscribers() == 1
    bus.publish("draft.changed")
    got = drain(sub)
    assert [e.type for e in got] == ["hello", "draft.changed"]
    assert got[0].data == {"server_id": bus.server_id, "last_id": 1}
    assert got[0].id == 1 and got[1].id == 2
    sub.close()
    assert bus.subscribers() == 0
    with pytest.raises(Closed):
        asyncio.run(sub.next(0.01))


def test_replay_after_an_id():
    bus = EventBus()
    for n in range(5):
        bus.publish("job.progress", {"done": n})
    sub = bus.subscribe(after=3)
    got = drain(sub)
    assert [(e.type, e.id) for e in got] == [("hello", 3), ("job.progress", 4), ("job.progress", 5)]
    # A page that has all events gets only hello.
    assert [e.type for e in drain(bus.subscribe(after=5))] == ["hello"]


def test_resync_when_the_id_is_older_than_the_buffer_or_from_another_process():
    bus = EventBus(keep=4)
    for n in range(10):
        bus.publish("job.progress", {"done": n})
    old = drain(bus.subscribe(after=2))  # the bus has 7 to 10 only
    assert [e.type for e in old] == ["hello", "resync"]
    assert old[1].data == {"server_id": bus.server_id, "last_id": 10}
    assert old[1].id == 10
    edge = drain(bus.subscribe(after=6))  # 7 is the oldest: nothing is lost
    assert [e.id for e in edge] == [6, 7, 8, 9, 10]
    other = drain(bus.subscribe(after=400))  # an id of an earlier server process
    assert [e.type for e in other] == ["hello", "resync"]


def test_a_slow_subscriber_gets_resync_after_overflow():
    bus = EventBus(queue=8)
    sub = bus.subscribe()
    for n in range(30):
        bus.publish("job.progress", {"done": n})
    got = drain(sub)
    assert [e.type for e in got] == ["resync"]  # the queue, with hello, was dropped
    assert got[0].data["last_id"] == 30
    bus.publish("job.progress", {"done": 31})
    assert [e.id for e in drain(sub)] == [31]


def test_publish_from_many_threads_keeps_one_order():
    bus = EventBus(keep=5000, queue=5000)
    sub = bus.subscribe()

    def work(n: int) -> None:
        for i in range(200):
            bus.publish("job.progress", {"thread": n, "i": i})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    got = [e for e in drain(sub, limit=5000) if e.type != "hello"]
    assert [e.id for e in got] == list(range(1, 1601))
    for n in range(8):  # each thread keeps its own order
        assert [e.data["i"] for e in got if e.data["thread"] == n] == list(range(200))


def test_next_wakes_on_a_publish_from_another_thread_and_times_out():
    bus = EventBus()
    sub = bus.subscribe()

    async def run():
        assert (await sub.next(1)).type == "hello"
        assert await sub.next(0.01) is None  # the caller sends a keep-alive
        threading.Timer(0.05, bus.publish, args=("ring.changed",)).start()
        event = await sub.next(5)
        assert event is not None and event.type == "ring.changed"
        threading.Timer(0.05, bus.close).start()
        with pytest.raises(Closed):
            await sub.next(5)

    asyncio.run(run())
    assert bus.subscribers() == 0


def test_frame_is_one_sse_frame():
    bus = EventBus(clock=lambda: 1_792_065_600)
    event = bus.publish("source.progress", {"id": "src_1", "label": "line\nbreak"})
    text = frame(event)
    assert text.endswith("\n\n") and text.count("\n") == 4
    lines = text.strip().split("\n")
    assert lines[0] == "id: 1" and lines[1] == "event: source.progress"
    assert json.loads(lines[2].removeprefix("data: ")) == {
        "v": 1,
        "id": 1,
        "at": "2026-10-15T12:00:00Z",
        "type": "source.progress",
        "topic": "source",
        "key": "src_1",
        "data": {"id": "src_1", "label": "line\nbreak"},
    }


# ---------------------------------------------------------- stream route


def parse(body: str) -> list[dict]:
    """The frames of a stream body. A comment line is `{"comment": …}`."""
    out = []
    for block in body.split("\n\n"):
        if not block:
            continue
        if block.startswith(":"):
            out.append({"comment": block})
            continue
        lines = dict(line.split(": ", 1) for line in block.split("\n"))
        data = json.loads(lines["data"])
        assert str(data["id"]) == lines["id"] and data["type"] == lines["event"]
        out.append(data)
    return out


@pytest.fixture
def app(tmp_path):
    return create_ui_app(UIService(tmp_path / "home"), port=PORT, token=TOKEN)


def read_stream(
    app, headers: dict | None = None, after: float | None = 0.3
) -> tuple[object, list[dict]]:
    """GET /api/events with the cookie. The stream ends when the bus closes:
    after `after` seconds, or (with None) when the caller closes it."""
    tc = TestClient(app, base_url=BASE)
    assert tc.get(f"/open/{TOKEN}", follow_redirects=False).status_code == 303
    if after is not None:
        threading.Timer(after, app.state.ctx.bus.close).start()
    r = tc.get("/api/events", headers=headers or {})
    assert r.status_code == 200
    return r, parse(r.text)


def test_stream_needs_the_cookie_the_host_and_the_origin(app):
    tc = TestClient(app, base_url=BASE)
    r = tc.get("/api/events")
    assert r.status_code == 401 and r.json()["launch"] is True
    assert tc.get("/api/events", headers={"Host": "evil.example"}).status_code == 421
    assert tc.get("/api/events", headers={"Host": f"rebind.example:{PORT}"}).status_code == 421
    assert tc.get("/api/events", headers={"Origin": "http://evil.example"}).status_code == 403
    assert tc.get("/api/events", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert tc.post("/api/events", headers={"Origin": BASE}).status_code == 401
    tc.cookies.set(cookie_name(PORT), "wrong")
    assert tc.get("/api/events").status_code == 401
    assert app.state.ctx.bus.subscribers() == 0


def test_stream_sends_hello_first_and_then_events(app):
    bus = app.state.ctx.bus
    bus.publish("ring.changed")
    threading.Timer(0.1, bus.publish, args=("source.progress", {"id": "s1", "done": 2})).start()
    r, frames = read_stream(app)
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in r.headers
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert [f["type"] for f in frames] == ["hello", "source.progress"]
    assert frames[0]["data"] == {"server_id": bus.server_id, "last_id": 1}
    assert frames[1] == {
        "v": 1,
        "id": 2,
        "at": frames[1]["at"],
        "type": "source.progress",
        "topic": "source",
        "key": "s1",
        "data": {"id": "s1", "done": 2},
    }
    assert bus.subscribers() == 0  # the stream ended and freed its queue


def test_stream_replays_after_last_event_id(app):
    bus = app.state.ctx.bus
    for n in range(4):
        bus.publish("job.progress", {"done": n})
    _, frames = read_stream(app, {"Last-Event-ID": "2"})
    assert [(f["type"], f["id"]) for f in frames] == [
        ("hello", 2),
        ("job.progress", 3),
        ("job.progress", 4),
    ]


def test_stream_sends_resync_for_an_id_that_the_bus_does_not_have(tmp_path):
    bus = EventBus(keep=2)
    app = create_ui_app(UIService(tmp_path / "home"), port=PORT, token=TOKEN, bus=bus)
    for n in range(6):
        bus.publish("job.progress", {"done": n})
    _, frames = read_stream(app, {"Last-Event-ID": "1"})
    assert [f["type"] for f in frames] == ["hello", "resync"]
    assert frames[1]["data"] == {"server_id": bus.server_id, "last_id": 6}


def test_a_last_event_id_that_is_not_a_number_is_a_new_page(app):
    assert events_route.last_event_id(None) is None
    for bad in ("", "abc", "-1", "1.5", "٣", "9" * 30):
        assert events_route.last_event_id(bad) is None, bad
    assert events_route.last_event_id("41") == 41
    app.state.ctx.bus.publish("ring.changed")
    _, frames = read_stream(app, {"Last-Event-ID": "abc"})
    assert [(f["type"], f["id"]) for f in frames] == [("hello", 1)]


def test_stream_sends_a_keep_alive_comment(app, monkeypatch):
    monkeypatch.setattr(events_route, "KEEPALIVE_S", 0.05)
    bus = app.state.ctx.bus

    # Close the bus only after the stream has subscribed, so that a slow
    # start under load does not end the stream before a keep-alive.
    def close_after_subscribe() -> None:
        wait_for(lambda: bus.subscribers() > 0)
        time.sleep(0.5)
        bus.close()

    threading.Thread(target=close_after_subscribe, daemon=True).start()
    _, frames = read_stream(app, after=None)
    assert frames[0]["type"] == "hello"
    assert frames[1:] and all(f == {"comment": ": keep-alive"} for f in frames[1:])


def wait_for(check, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.01)
    return False


def open_stream(server: UIServer) -> http.client.HTTPConnection:
    """A real connection to the loopback UI server, with the cookie. It has
    read the hello frame."""
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    conn.request("GET", f"/open/{server.token}")
    r = conn.getresponse()
    r.read()
    assert r.status == 303
    cookie = r.getheader("set-cookie").split(";")[0]
    conn.request("GET", "/api/events", headers={"Cookie": cookie})
    r = conn.getresponse()
    assert r.status == 200
    assert r.readline() == f"id: {server.app.state.ctx.bus.last_id}\n".encode()
    assert r.readline() == b"event: hello\n"
    conn.stream = r
    return conn


def test_a_closed_page_frees_its_subscription(tmp_path, monkeypatch):
    monkeypatch.setattr(events_route, "KEEPALIVE_S", 0.05)
    server = UIServer(UIService(tmp_path / "home")).start()
    bus = server.app.state.ctx.bus
    try:
        first, second = open_stream(server), open_stream(server)
        assert wait_for(lambda: bus.subscribers() == 2)
        first.stream.close()
        first.close()  # the tab closes: the keep-alive write fails
        assert wait_for(lambda: bus.subscribers() == 1)
        bus.publish("ring.changed")  # the other page still gets events
        seen = b""
        while b"event: ring.changed" not in seen:
            line = second.stream.readline()
            assert line, "the stream ended"
            seen += line
        second.stream.close()
        second.close()
        assert wait_for(lambda: bus.subscribers() == 0)
    finally:
        server.stop()


def test_the_server_stops_while_a_page_has_the_stream_open(tmp_path):
    server = UIServer(UIService(tmp_path / "home")).start()
    conn = open_stream(server)
    assert wait_for(lambda: server.app.state.ctx.bus.subscribers() == 1)
    start = time.monotonic()
    server.stop()
    assert not server.thread.is_alive()
    assert time.monotonic() - start < 8
    assert wait_for(lambda: not any(b.is_alive() for b in server.live.bridges))
    conn.close()


# -------------------------------------------------------------- publisher


def published(bus: EventBus, after: int = 0) -> list[tuple[str, dict]]:
    return [(e.type, e.data) for e in drain(bus.subscribe(after=after)) if e.type != "hello"]


def test_publisher_sends_to_the_attached_bus_only():
    publish, old, new = Publisher(), EventBus(), EventBus()
    publish("ring.changed")  # no bus yet: the event goes nowhere
    publish.attach(old)
    publish("ring.changed")
    publish.attach(new)  # a second app for the same service
    publish("finding.changed", {"id": "x"})
    assert published(old) == [("ring.changed", {})]
    assert published(new) == [("finding.changed", {"id": "x"})]


def test_the_app_attaches_its_bus_to_the_service(tmp_path):
    svc = UIService(tmp_path / "home")
    app = create_ui_app(svc, port=PORT, token=TOKEN)
    svc.publish("overview.changed")
    assert published(app.state.ctx.bus) == [("overview.changed", {})]


# ---------------------------------------------------------------- bridges


class JoinStub:
    def __init__(self) -> None:
        self.task = None
        self.view = {"state": "idle"}

    def status(self) -> dict:
        return dict(self.view)


def test_join_bridge_publishes_each_change_of_the_join_state():
    service, bus = JoinStub(), EventBus()
    b = JoinBridge(service, bus)
    b.tick()
    assert published(bus) == []  # no join runs
    service.task = object()
    service.view = {"state": "signin", "authorize_url": "https://node.test/a", "error": None}
    b.tick()
    b.tick()  # no change: no event
    service.view = {"state": "working", "authorize_url": None, "error": None}
    b.tick()
    service.view = {"state": "joined", "authorize_url": None, "error": None}
    b.tick()
    b.tick()
    service.task = None  # sign out
    b.tick()
    assert [(t, d.get("state")) for t, d in published(bus)] == [
        ("join.state", "signin"),
        ("join.state", "working"),
        ("join.state", "joined"),
        ("overview.changed", None),
        ("join.state", "idle"),
    ]


def test_join_bridge_publishes_overview_changed_after_an_orcid_link():
    """A link of an ORCID iD ends in the state `linked`: the account changes."""
    service, bus = JoinStub(), EventBus()
    b = JoinBridge(service, bus)
    service.task = object()
    service.view = {"state": "signin", "authorize_url": "https://node.test/a", "error": None}
    b.tick()
    service.view = {"state": "linked", "authorize_url": None, "error": None}
    b.tick()
    b.tick()  # no change: no event
    assert [(t, d.get("state")) for t, d in published(bus)] == [
        ("join.state", "signin"),
        ("join.state", "linked"),
        ("overview.changed", None),
    ]


def chen_pi(sim) -> dict:
    people = sim.ground_truth["people"]
    return next(p for p in people if p["role"] == "pi" and p["lab_id"] == "fake-lab-chen")


def test_events_of_a_real_join_and_a_real_source(tmp_path, sim_community):
    """The UI of today, through the JSON API: the service calls publish."""
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "chen", sim_community)
    bus = tc.app.state.ctx.bus
    join_bridge = JoinBridge(svc.join, bus)
    launched(tc)
    pi = chen_pi(sim_community)
    svc.join.prepare(net.invite(), name=pi["name"])
    join_bridge.tick()
    join_via_ui(net, svc, tc, None, pi["name"], prepare=False)
    join_bridge.tick()
    states = [d["state"] for t, d in published(bus) if t == "join.state"]
    assert states == ["joined"]
    assert ("overview.changed", {}) in published(bus)

    # A part publishes after an action returns, and not after an error.
    mark = bus.last_id
    assert tc.post("/api/rings", json={"name": "Friends"}, headers=ORIGIN).status_code == 200
    assert published(bus, mark) == [("ring.changed", {})]
    mark = bus.last_id
    r = tc.post("/api/rings/Absent/members", json={"member": "x"}, headers=ORIGIN)
    assert r.status_code == 400
    assert published(bus, mark) == []

    mark = bus.last_id
    assert tc.post("/api/recovery-kit/saved", headers=ORIGIN).json() == {"saved": True}
    assert published(bus, mark) == [("overview.changed", {})]

    lab = next(x for x in sim_community.ground_truth["labs"] if x["slug"] == "chen")
    mark = bus.last_id
    r = tc.post(
        "/api/sources",
        json={"kind": "folder", "path": str(sim_community.out_dir / lab["path"])},
        headers=ORIGIN,
    )
    assert r.status_code == 200 and r.json()["added"] >= 3
    # Source events go to the table `source_event`; a bridge
    # moves them to the bus.
    assert published(bus, mark) == []
    with svc.session(index=True) as (_, idx):
        rows = source_state.events_after(idx.store, 0)
    assert [e["topic"] for e in rows].count("source.added") == r.json()["added"]
    assert str(sim_community.out_dir) not in json.dumps(rows)
    # A refused call publishes nothing, and no path or content is in an event.
    r = tc.post("/api/sources", json={"kind": "folder", "path": "/absent"}, headers=ORIGIN)
    assert r.status_code == 400
    assert published(bus, mark) == []
    text = json.dumps([e.json() for e in drain(bus.subscribe(after=0))])
    assert str(sim_community.out_dir) not in text and str(tmp_path) not in text

    # The page gets the same events on the stream.
    threading.Timer(0.3, bus.close).start()
    frames = parse(tc.get("/api/events", headers={"Last-Event-ID": str(mark - 1)}).text)
    assert [f["type"] for f in frames] == ["hello", "overview.changed"]


def test_a_bridge_that_fails_logs_the_class_and_runs_again(caplog):
    class Broken(bridge._Poller):
        def __init__(self) -> None:
            super().__init__("broken-bridge", 0.01)
            self.ticks = 0

        def tick(self) -> None:
            self.ticks += 1
            raise RuntimeError("secret /Users/person")

    b = Broken()
    with caplog.at_level("WARNING", logger="anagram.shell.ui.bridge"):
        b.start()
        assert wait_for(lambda: b.ticks >= 3)
        b.stop()
        b.join(5)
    assert caplog.text.count("broken-bridge failed: RuntimeError") == 1
    assert "secret" not in caplog.text


def test_live_starts_and_stops_the_bridges_and_the_tasks(app):
    live = Live(app.state.ctx.service, app.state.ctx)
    assert [type(b) for b in live.bridges] == [JoinBridge, SourceEventBridge]
    runs = []
    app.state.ctx.tasks._ready = lambda: True
    app.state.ctx.tasks.add("probe", lambda: runs.append(1), 0.01)
    live.start()
    assert wait_for(lambda: runs and all(b.is_alive() for b in live.bridges))
    live.stop()
    assert app.state.ctx.bus.closed
    assert wait_for(lambda: not any(b.is_alive() for b in live.bridges))


def test_source_event_bridge_moves_each_row_to_the_bus(tmp_path, sim_community):
    """A row of `source_event` reaches the page as one event, and
    source work makes the drafts stale."""
    net = make_net(tmp_path)
    svc, tc = ui_client(net, tmp_path / "chen", sim_community)
    launched(tc)
    pi = chen_pi(sim_community)
    setup_person(net, svc, tc, sim_community, pi["orcid"], pi["name"], "chen")
    bus = EventBus()
    b = SourceEventBridge(svc, bus)
    b.tick()
    assert b.last is None  # no page is open: the bridge does not read
    sub = bus.subscribe()
    b.tick()  # the first read is the base: older rows are in GET /api/sources
    base = b.last
    lab = next(x for x in sim_community.ground_truth["labs"] if x["slug"] != "chen")
    r = tc.post(
        "/api/sources",
        json={"kind": "folder", "path": str(sim_community.out_dir / lab["path"])},
        headers=ORIGIN,
    )
    added = r.json()["added"]
    assert added >= 1
    with svc.session(index=True) as (_, idx):
        rows = source_state.events_after(idx.store, base)
    b.tick()
    got = [e for e in drain(sub) if e.type != "hello"]
    assert [e.type for e in got] == [row["topic"] for row in rows] + ["draft.changed"]
    first = [e for e in got if e.type == "source.added"]
    assert len(first) == added
    assert all(e.key == e.data["source"]["id"] for e in first)
    assert b.last == rows[-1]["id"]
    b.tick()  # nothing new: nothing published
    assert [e.type for e in drain(sub)] == []
    assert str(sim_community.out_dir) not in json.dumps([e.data for e in got])
    sub.close()


def test_add_source_route_passes_the_whole_body(tmp_path):
    """POST /api/sources gives each field to the sources service, not only kind and path."""
    svc = UIService(tmp_path / "home")
    got = []

    class Spy:
        def add(self, body, refresh=True):
            got.append(body)
            return {"added": 0, "found": "", "sources": []}

    svc.sources = Spy()
    from anagram.shell.ui.server import create_ui_app

    app = create_ui_app(svc, port=8123, token="t")  # noqa: S106 - a test token
    tc = TestClient(app, base_url="http://127.0.0.1:8123")
    tc.get("/open/t", follow_redirects=False)
    body = {"kind": "folder", "path": "/x", "space": "lab:abc", "label": "Notes"}
    r = tc.post("/api/sources", json=body, headers={"Origin": "http://127.0.0.1:8123"})
    assert r.status_code == 200
    assert got == [body]
    r = tc.post("/api/sources", json={"path": "/x"}, headers={"Origin": "http://127.0.0.1:8123"})
    assert r.status_code == 400
