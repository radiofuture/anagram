"""The control route, one-time open links, the runtime file, and the
launcher. The app runs in this process on a
loopback port. No real keychain. Each test stops its app."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import httpx
import pytest
from conftest import free_port, make_net
from fastapi.testclient import TestClient
from test_app_runtime import FakeIndexer

from anagram.shell.app import control, launcher
from anagram.shell.app.control import OpenTokens, read_runtime, runtime_path
from anagram.shell.app.runtime import AppRuntime
from anagram.shell.cli.main import main
from anagram.shell.ui.server import create_ui_app
from anagram.shell.ui.service import UIService


@pytest.fixture
def app(tmp_path):
    made: list[AppRuntime] = []

    def start(home, **kw):
        rt = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer(), **kw)
        rt.start()
        made.append(rt)
        return rt

    yield start
    for rt in made:
        rt.stop()


def ctl(rt, path, body=None, headers=None, bearer=True):
    h = {"Authorization": f"Bearer {rt.control}"} if bearer else {}
    h.update(headers or {})
    return httpx.post(f"http://127.0.0.1:{rt.port}{path}", json=body or {}, headers=h, timeout=5)


def browser_client(rt) -> httpx.Client:
    return httpx.Client(base_url=f"http://127.0.0.1:{rt.port}", timeout=5)


# ------------------------------------------------------------------- control


def test_control_refuses_browser_requests(tmp_path, app):
    rt = app(tmp_path / "h")
    origin = f"http://127.0.0.1:{rt.port}"
    for extra in (
        {"Origin": origin},
        {"Origin": "https://evil.example"},
        {"Cookie": "a=b"},
        {"Sec-Fetch-Site": "same-origin"},
        {"Sec-Fetch-Site": "cross-site"},
    ):
        r = ctl(rt, "/control/open", headers=extra)
        assert r.status_code == 403, extra
    assert ctl(rt, "/control/open", bearer=False).status_code == 401
    r = ctl(rt, "/control/open", headers={"Authorization": "Bearer wrong"}, bearer=False)
    assert r.status_code == 401
    r = httpx.post(
        f"{origin}/control/open",
        headers={"Authorization": f"Bearer {rt.control}", "Host": "evil.example"},
        timeout=5,
    )
    assert r.status_code == 421
    r = ctl(rt, "/control/open")
    assert r.status_code == 200 and r.json()["url"].startswith(f"{origin}/open/")
    assert "set-cookie" not in r.headers
    assert ctl(rt, "/control/open", {"route": "nope"}).status_code == 400


def test_no_control_routes_without_the_app(tmp_path):
    svc = UIService(tmp_path / "h")
    ui = create_ui_app(svc, port=41998, token="t")  # noqa: S106 - a test value
    tc = TestClient(ui, base_url="http://127.0.0.1:41998")
    r = tc.post("/control/open", headers={"Authorization": "Bearer x"}, json={})
    assert r.status_code == 404
    assert tc.get("/health").status_code in (401, 404)


def test_open_token_one_use(tmp_path, app):
    rt = app(tmp_path / "h")
    url = ctl(rt, "/control/open", {"route": "settings"}).json()["url"]
    c = browser_client(rt)
    r = c.get(url, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/#/account"
    assert c.get("/api/overview").status_code == 200  # the cookie works
    again = httpx.get(url, follow_redirects=False, timeout=5)
    assert again.status_code == 403
    assert httpx.get(f"http://127.0.0.1:{rt.port}/api/overview", timeout=5).status_code == 401


def test_open_tokens_expire_and_are_limited():
    now = [0.0]
    tokens = OpenTokens(ttl=60, limit=2, clock=lambda: now[0])
    a = tokens.mint()
    now[0] = 61
    assert tokens.redeem(a) is None  # too old
    b, c, d = tokens.mint("join"), tokens.mint(), tokens.mint("recover")
    assert tokens.redeem(b) is None  # the oldest went when the limit was passed
    assert tokens.redeem(c) == "/" and tokens.redeem(d) == "/#/welcome/recover"
    assert tokens.redeem(d) is None
    with pytest.raises(ValueError):
        tokens.mint("../x")


def test_invite_is_pending_only(tmp_path, app):
    net = make_net(tmp_path)
    home = tmp_path / "new"
    rt = app(home, service=UIService(home, transport=net.transport, clock=net.clock))
    invite = net.invite()
    url = ctl(rt, "/control/open", {"invite": invite}).json()["url"]
    c = browser_client(rt)
    assert c.get(url, follow_redirects=False).headers["location"] == "/#/welcome"
    assert rt.service.state.get("pending_invite") == {"kind": "node", "url": invite}
    assert not rt.service.joined() and rt.service.join.task is None  # no sign-in started
    assert c.get("/api/join").json()["invite"] == invite
    # Text that is not an invite is ignored; the app opens with no data.
    url = ctl(rt, "/control/open", {"invite": "https://evil.example/x"}).json()["url"]
    assert browser_client(rt).get(url, follow_redirects=False).headers["location"] == "/"
    assert rt.service.state.get("pending_invite")["url"] == invite


def test_node_invite_ignored_when_joined(tmp_path, app):
    net = make_net(tmp_path)
    home = tmp_path / "me"
    net.join(home, "fake-ctl", "Ctl Person").client.vault.close()
    rt = app(home, service=UIService(home, transport=net.transport, clock=net.clock))
    before = rt.service.state.load()
    url = ctl(rt, "/control/open", {"invite": net.invite()}).json()["url"]
    assert browser_client(rt).get(url, follow_redirects=False).headers["location"] == "/"
    assert rt.service.state.load() == before


def test_control_stop(tmp_path, app):
    rt = app(tmp_path / "h")
    assert ctl(rt, "/control/stop").json() == {"stopping": True}
    assert rt._done.is_set()


# -------------------------------------------------------------- runtime file


def test_runtime_file(tmp_path, app):
    home = tmp_path / "h"
    rt = app(home)
    path = runtime_path(home)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    doc = read_runtime(home)
    assert set(doc) == {"control", "instance", "pid", "port", "schema", "started_at", "version"}
    assert doc["control"] == rt.control and len(doc["control"]) == 43
    assert doc["instance"] == rt.instance and doc["port"] == rt.port and doc["pid"] == os.getpid()
    assert rt.server.server.config.access_log is False
    rt.stop()
    assert not path.exists()


# ------------------------------------------------------------------ launcher


def test_launcher_against_a_live_app(tmp_path, app):
    home = tmp_path / "h"
    rt = app(home)
    opened = []

    def no_start(_):
        raise AssertionError("the app runs; the launcher must not start it")

    url = launcher.open_app(home, route="join", start=no_start, browser=opened.append)
    assert opened == [url] and url.startswith(f"http://127.0.0.1:{rt.port}/open/")
    r = browser_client(rt).get(url, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/#/welcome"


def test_launcher_starts_the_app(tmp_path, app):
    home = tmp_path / "h"
    started = []
    url = launcher.open_app(
        home, start=lambda h: started.append(app(h)), browser=lambda u: None, wait_s=10
    )
    assert len(started) == 1 and url.startswith(f"http://127.0.0.1:{started[0].port}/open/")


def test_stale_runtime_file_with_a_dead_pid(tmp_path, app):
    home = tmp_path / "h"
    dead = subprocess.Popen([sys.executable, "-c", "pass"])  # noqa: S603 - this interpreter
    dead.wait()
    control.write_runtime(
        home,
        {
            "control": "x" * 43,
            "instance": "0" * 16,
            "pid": dead.pid,
            "port": free_port(),
            "schema": control.RUNTIME_SCHEMA,
            "started_at": "2026-11-16T10:00:00Z",
            "version": "0.0.0",
        },
    )
    assert launcher.live_runtime(home) is None
    assert not runtime_path(home).exists()
    started = []
    launcher.open_app(home, start=lambda h: started.append(app(h)), browser=lambda u: None)
    assert read_runtime(home)["instance"] == started[0].instance


def test_launcher_gives_up(tmp_path):
    with pytest.raises(launcher.LaunchError):
        launcher.ensure_running(tmp_path / "h", start=lambda h: None, wait_s=0.3)


def test_service_command(tmp_path):
    cmd = launcher.service_command(tmp_path)
    assert cmd[:3] == [sys.executable, "-m", "anagram"]
    assert cmd[3:] == ["--home", str(tmp_path.resolve()), "app", "run"]


def test_open_and_stop_commands(tmp_path, app, capsys, monkeypatch):
    home = tmp_path / "h"
    rt = app(home)
    opened = []
    monkeypatch.setattr(launcher.webbrowser, "open", opened.append)
    assert main(["--home", str(home), "open", "--route", "settings"]) == 0
    assert len(opened) == 1
    r = browser_client(rt).get(opened[0], follow_redirects=False)
    assert r.headers["location"] == "/#/account"
    assert main(["--home", str(home), "app", "stop"]) == 0
    assert rt._done.is_set()
    time.sleep(0)
