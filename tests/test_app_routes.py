"""App routes of the local UI (R1 S8): /api/app, start at login, restart the
helper, recover from a kit, and the shape of /api/recovery-kit."""

from __future__ import annotations

import pytest
from conftest import make_net
from fastapi.testclient import TestClient
from test_app_runtime import FakeIndexer, helper_events, launched, started, wait_for  # noqa: F401
from test_autostart import FakeRun

import anagram
from anagram.shell.app import autostart as autostart_pkg
from anagram.shell.app.autostart import (
    LaunchdAutostart,
    NoAutostart,
    SystemdAutostart,
    service_command,
)
from anagram.shell.ui.server import create_ui_app
from anagram.shell.ui.service import UIService

PORT = 8787
BASE = f"http://127.0.0.1:{PORT}"
TOKEN = "t" * 32
ORIGIN = {"Origin": BASE}


class FakeRuntime:
    """The part of AppRuntime that the routes use."""

    def __init__(self, autostart):
        self.autostart = autostart
        self.restarts = 0

    def status(self) -> dict:
        return {
            "errors": 0,
            "last_cycle_at": None,
            "since": "2026-11-16T10:00:00Z",
            "state": "running",
        }

    def restart_helper(self) -> None:
        self.restarts += 1


def client(home, *, runtime=None, transport=None, clock=None) -> TestClient:
    svc = UIService(home, transport=transport, clock=clock)
    app = create_ui_app(svc, port=PORT, token=TOKEN, runtime=runtime)
    tc = TestClient(app, base_url=BASE)
    assert tc.get(f"/open/{TOKEN}", follow_redirects=False).status_code == 303
    return tc


@pytest.fixture
def systemd(tmp_path):
    run = FakeRun()
    return SystemdAutostart(root=tmp_path / "user", run=run), run


ROUTES = [
    ("GET", "/api/app", None),
    ("PUT", "/api/app/start-at-login", {"on": True}),
    ("POST", "/api/app/restart-helper", {}),
    ("POST", "/api/recover", {"kit": "x"}),
]


@pytest.mark.parametrize(("method", "path", "body"), ROUTES)
def test_each_route_needs_the_cookie(tmp_path, systemd, method, path, body):
    svc = UIService(tmp_path / "me")
    app = create_ui_app(svc, port=PORT, token=TOKEN, runtime=FakeRuntime(systemd[0]))
    tc = TestClient(app, base_url=BASE)
    r = tc.request(method, path, json=body, headers=ORIGIN)
    assert r.status_code == 401 and r.json()["launch"] is True


def test_app_view_shape(tmp_path, systemd):
    tc = client(tmp_path / "me", runtime=FakeRuntime(systemd[0]))
    r = tc.get("/api/app")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"helper", "keys", "start_at_login", "update", "version"}
    assert set(body["helper"]) == {"errors", "last_cycle_at", "since", "state"}
    assert body["helper"]["state"] == "running"
    assert body["keys"] == {"backend": "file", "protected": False}
    assert body["start_at_login"] == {"manager": "systemd", "on": False}
    assert body["update"] == {"available": False, "url": None, "version": None}
    assert body["version"] == anagram.__version__
    assert str(tmp_path) not in r.text  # no raw path


def test_start_at_login_changes_only_the_next_login(tmp_path, systemd):
    a, run = systemd
    home = tmp_path / "me"
    tc = client(home, runtime=FakeRuntime(a))
    r = tc.put("/api/app/start-at-login", json={"on": True}, headers=ORIGIN)
    assert r.status_code == 200 and r.json() == {"manager": "systemd", "on": True}
    assert a.command() == service_command(home)
    # Enabled for the next login; the running app is not started a second time.
    assert ["systemctl", "--user", "enable", "anagram.service"] in run.calls
    assert not any("--now" in c for c in run.calls)
    assert tc.get("/api/app").json()["start_at_login"]["on"] is True
    run.calls.clear()
    assert tc.put("/api/app/start-at-login", json={"on": True}, headers=ORIGIN).json()["on"]
    assert run.calls == []  # already on: no change
    r = tc.put("/api/app/start-at-login", json={"on": False}, headers=ORIGIN)
    assert r.json() == {"manager": "systemd", "on": False} and not a.installed()
    assert ["systemctl", "--user", "disable", "anagram.service"] in run.calls
    assert not any("--now" in c for c in run.calls)  # the running app does not stop


def test_start_at_login_off_keeps_the_unit_of_another_home(tmp_path, systemd):
    a, _ = systemd
    other = service_command(tmp_path / "other")
    a.install(other)
    tc = client(tmp_path / "me", runtime=FakeRuntime(a))
    assert tc.get("/api/app").json()["start_at_login"]["on"] is False
    tc.put("/api/app/start-at-login", json={"on": False}, headers=ORIGIN)
    assert a.command() == other


def test_start_at_login_errors(tmp_path):
    a = NoAutostart(root=tmp_path, run=FakeRun())
    tc = client(tmp_path / "me", runtime=FakeRuntime(a))
    r = tc.put("/api/app/start-at-login", json={"on": True}, headers=ORIGIN)
    assert r.status_code == 409 and "start at login" in r.json()["error"]
    for bad in ({}, {"on": "yes"}, {"on": 1}):
        assert tc.put("/api/app/start-at-login", json=bad, headers=ORIGIN).status_code == 400


def test_restart_helper(tmp_path, systemd):
    rt = FakeRuntime(systemd[0])
    tc = client(tmp_path / "me", runtime=rt)
    r = tc.post("/api/app/restart-helper", json={}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["state"] == "running" and rt.restarts == 1


def test_without_the_app_runtime(tmp_path, monkeypatch):
    # `anagram ui` (a developer): no helper thread; the login service of the system.
    run = FakeRun()
    monkeypatch.setattr(
        autostart_pkg,
        "autostart_for_platform",
        lambda: LaunchdAutostart(root=tmp_path / "user", run=run, uid=501),
    )
    tc = client(tmp_path / "me")
    body = tc.get("/api/app").json()
    assert body["helper"]["state"] == "stopped"
    assert body["start_at_login"] == {"manager": "launchd", "on": False}
    r = tc.post("/api/app/restart-helper", json={}, headers=ORIGIN)
    assert r.status_code == 409
    tc.put("/api/app/start-at-login", json={"on": True}, headers=ORIGIN)
    assert run.calls == []  # the plist is written; launchd loads it at the next login


def test_launchd_and_systemd_switch_without_the_running_app(tmp_path):
    run = FakeRun()
    a = LaunchdAutostart(root=tmp_path, run=run, uid=501)
    a.install(["x", "--home", "h", "app", "run"], start=False)
    a.uninstall(stop=False)
    assert run.calls == [] and not a.installed()
    run = FakeRun()
    s = SystemdAutostart(root=tmp_path, run=run)
    s.install(["x"], start=False)
    s.uninstall(stop=False)
    assert run.calls == [
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "anagram.service"],
        ["systemctl", "--user", "disable", "anagram.service"],
        ["systemctl", "--user", "daemon-reload"],
    ]


def test_routes_on_the_app_runtime(tmp_path, started, systemd):  # noqa: F811
    rt = started(tmp_path / "h", make_indexer=lambda s: FakeIndexer(), autostart=systemd[0])
    c = launched(rt)
    assert wait_for(lambda: c.get("/api/app").json()["helper"]["state"] == "running")
    before = len(helper_events(rt))
    r = c.post("/api/app/restart-helper", json={}, headers={"Origin": str(c.base_url).rstrip("/")})
    assert r.status_code == 200 and r.json()["state"] in ("starting", "running")
    assert len(helper_events(rt)) > before  # the runtime published app.helper
    c.close()


# -------------------------------------------------------------------- recover


def test_recover_from_a_kit(tmp_path, systemd):
    net = make_net(tmp_path)
    r = net.join(tmp_path / "old", "fake-forgetful")
    r.client.vault.close()
    kit, subject = r.kit_text, r.subject
    tc = client(
        tmp_path / "new",
        runtime=FakeRuntime(systemd[0]),
        transport=net.transport,
        clock=net.clock,
    )
    assert tc.get("/api/overview").json()["joined"] is False
    out = tc.post("/api/recover", json={"kit": kit}, headers=ORIGIN)
    assert out.status_code == 200 and out.json() == {"state": "restored", "subject": subject}
    view = tc.get("/api/overview").json()
    assert view["joined"] is True and view["kit_saved"] is True
    kit_view = tc.get("/api/recovery-kit").json()
    assert kit_view["pending"] is False and kit_view["saved"] is True
    again = tc.post("/api/recover", json={"kit": kit}, headers=ORIGIN)
    assert again.status_code == 409 and str(tmp_path) not in again.text


def test_recover_errors(tmp_path, systemd):
    net = make_net(tmp_path)
    r = net.join(tmp_path / "old", "fake-forgetful")
    r.client.vault.close()
    tc = client(
        tmp_path / "new", runtime=FakeRuntime(systemd[0]), transport=net.transport, clock=net.clock
    )
    for bad in ({}, {"kit": ""}, {"kit": 5}):
        assert tc.post("/api/recover", json=bad, headers=ORIGIN).status_code == 400
    r2 = tc.post("/api/recover", json={"kit": "hello"}, headers=ORIGIN)
    assert r2.status_code == 400 and "not an Anagram recovery kit" in r2.json()["error"]
    wrong = r.kit_text.replace(r.recovery_code, "A" * len(r.recovery_code))
    r3 = tc.post("/api/recover", json={"kit": wrong}, headers=ORIGIN)
    assert r3.status_code == 400
    # A refused kit leaves no data: the right kit still works.
    ok = tc.post("/api/recover", json={"kit": r.kit_text}, headers=ORIGIN)
    assert ok.status_code == 200


def test_recovery_kit_shape_keeps_the_keys_of_today(tmp_path, systemd):
    net = make_net(tmp_path)
    home = tmp_path / "me"
    r = net.join(home, "fake-kit")
    r.client.vault.close()
    tc = client(home, runtime=FakeRuntime(systemd[0]), transport=net.transport, clock=net.clock)
    body = tc.get("/api/recovery-kit").json()
    assert body["pending"] is True and body["saved"] is False and body["code"]
    assert body["available"] is True
    tc.post("/api/recovery-kit/saved", json={}, headers=ORIGIN)
    body = tc.get("/api/recovery-kit").json()
    assert body == {"available": False, "pending": False, "saved": True}
