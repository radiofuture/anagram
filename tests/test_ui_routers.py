"""Route discovery (`ui/routers`), the manifest and copy routes, and the task
runner (`shell/ui/tasks.py`). No network."""

from __future__ import annotations

import dataclasses
import inspect
import json
import logging
import sys
import textwrap
import threading
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from anagram.shell.ui import routers
from anagram.shell.ui.events import EventBus
from anagram.shell.ui.routers import UIContext, manifest, register_all, register_package
from anagram.shell.ui.server import cookie_name, create_ui_app
from anagram.shell.ui.service import UIService
from anagram.shell.ui.tasks import TaskRunner

PORT = 41998
TOKEN = "launch-token-for-tests"  # noqa: S105 - a test value
BASE = f"http://127.0.0.1:{PORT}"


@pytest.fixture
def service(tmp_path):
    return UIService(tmp_path / "home")


@pytest.fixture
def client(service):
    return TestClient(create_ui_app(service, port=PORT, token=TOKEN), base_url=BASE)


def launched(tc: TestClient) -> TestClient:
    assert tc.get(f"/open/{TOKEN}", follow_redirects=False).status_code == 303
    return tc


def package(tmp_path, monkeypatch, name: str, modules: dict[str, str]) -> str:
    """A package of route modules in a temp directory."""
    root = tmp_path / "pkgs"
    (root / name).mkdir(parents=True)
    (root / name / "__init__.py").write_text("")
    for module, body in modules.items():
        (root / name / f"{module}.py").write_text(textwrap.dedent(body))
    monkeypatch.syspath_prepend(str(root))
    for loaded in [m for m in sys.modules if m == name or m.startswith(name + ".")]:
        del sys.modules[loaded]
    return name


def context(service) -> UIContext:
    return UIContext(service, EventBus(), TaskRunner(), PORT)


# ------------------------------------------------------------- discovery


def test_context_has_the_contract_fields(service):
    fields = [(f.name, f.default) for f in dataclasses.fields(UIContext)]
    assert [n for n, _ in fields] == ["service", "bus", "tasks", "port", "runtime"]
    assert fields[-1][1] is None
    ctx = context(service)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.port = 1


def test_the_app_has_one_context_with_the_given_bus_and_tasks(service):
    bus, tasks = EventBus(), TaskRunner()
    app = create_ui_app(service, port=PORT, token=TOKEN, bus=bus, tasks=tasks)
    ctx = app.state.ctx
    assert (ctx.service, ctx.bus, ctx.tasks, ctx.port, ctx.runtime) == (
        service,
        bus,
        tasks,
        PORT,
        None,
    )
    assert isinstance(create_ui_app(service, port=PORT, token=TOKEN).state.ctx.bus, EventBus)


def test_register_all_finds_each_module_in_name_order(tmp_path, monkeypatch, service):
    name = package(
        tmp_path,
        monkeypatch,
        "r7_routers_a",
        {
            "zeta": """
                def register(app, ctx):
                    app.state.order.append("zeta")
                    @app.get("/api/zeta")
                    def zeta() -> dict:
                        return {"port": ctx.port}
            """,
            "alpha": """
                def register(app, ctx):
                    app.state.order.append("alpha")
                    ctx.tasks.add("alpha.watch", lambda: None, 60)
                    @app.post("/api/alpha")
                    def alpha() -> dict:
                        return {"event": ctx.bus.publish("alpha.done").id}
            """,
            "_private": "raise RuntimeError('not a route module')\n",
        },
    )
    app = FastAPI()
    app.state.order = []
    ctx = context(service)
    register_package(app, ctx, name)
    assert app.state.order == ["alpha", "zeta"]
    assert ctx.tasks.names() == ["alpha.watch"]
    tc = TestClient(app)
    assert tc.get("/api/zeta").json() == {"port": PORT}
    assert tc.post("/api/alpha").json() == {"event": 1}


def test_register_all_refuses_a_module_with_no_register(tmp_path, monkeypatch, service):
    name = package(tmp_path, monkeypatch, "r7_routers_b", {"empty": "x = 1\n"})
    with pytest.raises(RuntimeError, match="has no register"):
        register_package(FastAPI(), context(service), name)


def test_register_all_refuses_a_path_that_exists(tmp_path, monkeypatch, service):
    name = package(
        tmp_path,
        monkeypatch,
        "r7_routers_c",
        {
            "again": """
                def register(app, ctx):
                    @app.get("/api/overview")
                    def overview() -> dict:
                        return {}
            """
        },
    )
    app = FastAPI()

    @app.get("/api/overview")
    def overview() -> dict:
        return {}

    with pytest.raises(RuntimeError, match="registers GET /api/overview, which exists"):
        register_package(app, context(service), name)


def test_the_real_package_registers_with_no_path_twice(service):
    assert {"events", "manifest"} <= set(routers.module_names())
    assert list(inspect.signature(register_all).parameters) == ["app", "ctx"]
    publish = inspect.signature(EventBus.publish)
    assert (
        str(publish)
        == "(self, type: 'str', data: 'dict | None' = None, *, key: 'str | None' = None) -> 'Event'"
    )
    app = create_ui_app(service, port=PORT, token=TOKEN)
    paths = {r.path for r in app.routes}
    assert {"/api/ui/manifest", "/api/ui/copy", "/api/events", "/api/overview"} <= paths


# ------------------------------------------------------ manifest and copy


def test_new_routes_need_the_cookie_and_the_right_host(client):
    for path in ("/api/ui/manifest", "/api/ui/copy"):
        r = client.get(path)
        assert r.status_code == 401 and r.json()["launch"] is True, path
        assert client.get(path, headers={"Host": "evil.test"}).status_code == 421, path
        assert client.get(path, headers={"Origin": "http://evil.test"}).status_code == 403, path
    launched(client)
    r = client.get("/api/ui/manifest")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert set(r.json()) == {"screens", "slots", "styles", "build"}
    assert client.get("/api/ui/copy").status_code == 200


def test_manifest_lists_screens_slots_and_styles(tmp_path, monkeypatch, client):
    static = tmp_path / "static"
    for rel in (
        "js/screens/sources.js",
        "js/screens/account.js",
        "js/screens/notes.txt",
        "js/screens/Bad Name.js",
        "js/slots/computer.js",
        "css/screens/sources.css",
        "js/core/html.js",
    ):
        (static / rel).parent.mkdir(parents=True, exist_ok=True)
        (static / rel).write_text("x")
    monkeypatch.setattr(manifest, "STATIC", static)
    out = launched(client).get("/api/ui/manifest").json()
    assert out["screens"] == ["account.js", "sources.js"]
    assert out["slots"] == ["computer.js"]
    assert out["styles"] == ["sources.css"]
    assert len(out["build"]) == 64
    (static / "js/screens/sources.js").write_text("a longer file")
    assert client.get("/api/ui/manifest").json()["build"] != out["build"]
    # A directory that does not exist gives an empty list, not an error.
    monkeypatch.setattr(manifest, "STATIC", tmp_path / "absent")
    empty = client.get("/api/ui/manifest").json()
    assert (empty["screens"], empty["slots"], empty["styles"]) == ([], [], [])


def test_copy_is_the_merge_of_the_copy_files(tmp_path, monkeypatch, client):
    static = tmp_path / "static"
    (static / "copy").mkdir(parents=True)
    (static / "copy/sources.json").write_text(json.dumps({"title": "Sources", "add": "Add"}))
    (static / "copy/common.json").write_text(json.dumps({"back": "Back"}))
    (static / "copy/readme.txt").write_text("not copy")
    monkeypatch.setattr(manifest, "STATIC", static)
    launched(client)
    assert client.get("/api/ui/copy").json() == {
        "common": {"back": "Back"},
        "sources": {"title": "Sources", "add": "Add"},
    }
    (static / "copy/broken.json").write_text("{")
    r = client.get("/api/ui/copy")
    assert r.status_code == 500 and "broken.json" in r.json()["error"]


def test_the_cookie_name_has_the_port():
    assert cookie_name(PORT) == f"anagram_ui_{PORT}"


# ----------------------------------------------------------- task runner


def wait_for(check, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.005)
    return False


def test_a_task_runs_again_and_again_and_stops():
    runs = []
    tasks = TaskRunner()
    tasks.add("count", lambda: runs.append(1), every_s=0.01)
    assert tasks.names() == ["count"]
    assert not runs  # nothing runs before start()
    tasks.start()
    tasks.start()  # a second call does nothing
    assert wait_for(lambda: len(runs) >= 3)
    tasks.stop()
    n = len(runs)
    time.sleep(0.05)
    assert len(runs) == n
    assert len([t for t in threading.enumerate() if t.name == "task:count"]) == 0


def test_a_task_that_fails_is_logged_and_runs_again(caplog):
    runs = []

    def fails() -> None:
        runs.append(1)
        raise RuntimeError("secret-path /Users/person/notes")

    tasks = TaskRunner()
    tasks.add("lab.watch", fails, every_s=0.01)
    with caplog.at_level(logging.ERROR, logger="anagram.shell.ui.tasks"):
        tasks.start()
        assert wait_for(lambda: len(runs) >= 3)
        tasks.stop()
    assert "task lab.watch failed: RuntimeError" in caplog.text
    assert "secret-path" not in caplog.text  # the class and the name only


def test_a_task_does_not_run_before_the_member_has_joined():
    joined = threading.Event()
    runs = []
    tasks = TaskRunner(joined.is_set, ready_poll_s=0.01)
    tasks.add("shares.sync", lambda: runs.append(1), every_s=0.01)
    tasks.start()
    time.sleep(0.1)
    assert not runs
    joined.set()
    assert wait_for(lambda: len(runs) >= 1)
    tasks.stop()


def test_the_interval_can_be_a_function_and_a_task_can_be_added_after_start():
    asked, runs = [], []

    def every() -> float:
        asked.append(1)
        return 0.01

    tasks = TaskRunner()
    tasks.start()
    tasks.add("match.watch", lambda: runs.append(1), every)
    assert wait_for(lambda: len(runs) >= 2 and len(asked) >= 2)
    tasks.stop()


def test_task_names_are_unique_and_the_interval_is_positive():
    tasks = TaskRunner()
    tasks.add("b", lambda: None, 1)
    tasks.add("a", lambda: None, 1)
    assert tasks.names() == ["a", "b"]
    with pytest.raises(ValueError):
        tasks.add("a", lambda: None, 1)
    with pytest.raises(ValueError):
        tasks.add("c", lambda: None, 0)
    with pytest.raises(ValueError):
        tasks.add("", lambda: None, 1)


def test_the_app_task_runner_waits_for_the_join(service):
    app = create_ui_app(service, port=PORT, token=TOKEN)
    runs = []
    tasks = app.state.ctx.tasks
    tasks._ready_poll_s = 0.01
    tasks.add("probe", lambda: runs.append(1), 0.01)
    tasks.start()
    time.sleep(0.1)
    tasks.stop()
    assert not service.joined() and not runs
