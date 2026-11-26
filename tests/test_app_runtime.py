"""The app process (`AppRuntime`): one process, the helper thread, the
supervisor, the lock, the log. The node is the in-process test node; the UI
server listens on a loopback port. No real keychain. Each test stops its
runtime."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
from conftest import make_net

from anagram.local.index.indexer import Indexer
from anagram.local.index.scan import ScanReport
from anagram.shell.app import control, lock, logs, runtime
from anagram.shell.app.runtime import AlreadyRunning, AppRuntime
from anagram.shell.ui.server import UIServer, bind_local
from anagram.shell.ui.service import UIService

CANARY = "CANARY-LOG-7731"


def wait_for(cond, timeout=10.0, step=0.02):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return False


class FakeIndexer:
    """A helper with the loop of Indexer.run: step() until stop."""

    def __init__(self, step=None, fail=False):
        self._step = step
        self.fail = fail
        self.state = type("S", (), {"errors": [], "last_cycle_at": None})()

    def step(self):
        if self._step is not None:
            return self._step()
        return None

    def run(self, stop):
        if self.fail:
            raise RuntimeError(f"helper broke in /Users/x/{CANARY}")
        while not stop.is_set():
            self.step()
            stop.wait(0.01)


@pytest.fixture
def started():
    """Start runtimes; stop each at the end of the test."""
    made: list[AppRuntime] = []

    def start(home, **kw):
        kw.setdefault("tick_s", 0.05)
        kw.setdefault("embed", False)
        rt = AppRuntime(home, **kw)
        rt.start()
        made.append(rt)
        return rt

    yield start
    for rt in made:
        rt.stop()


@pytest.fixture
def joined(tmp_path):
    net = make_net(tmp_path)
    home = tmp_path / "me"
    r = net.join(home, "fake-app", "App Person")
    r.client.vault.close()
    svc = UIService(home, transport=net.transport, clock=net.clock)
    return net, home, svc


def launched(rt) -> httpx.Client:
    c = httpx.Client(base_url=f"http://127.0.0.1:{rt.port}", timeout=10)
    assert c.get(f"/open/{rt.server.token}").status_code in (200, 303)
    return c


def helper_events(rt) -> list[dict]:
    return [e.data for e in list(rt.ctx.bus._events) if e.type == "app.helper"]


# ------------------------------------------------------------------ process


def test_ui_answers_while_a_slow_scan_runs(joined, started):
    _, home, svc = joined
    inside, release = threading.Event(), threading.Event()

    def slow_step():
        # The helper has its own client and index; it does not take the UI lock.
        with svc.open_client(index=True) as (client, idx):
            assert client.device.subject and idx is not None
            inside.set()
            release.wait(10)

    rt = started(home, service=svc, make_indexer=lambda s: FakeIndexer(slow_step))
    try:
        assert inside.wait(10)
        c = launched(rt)
        t0 = time.monotonic()
        r = c.get("/api/overview")
        assert r.status_code == 200 and r.json()["joined"]
        assert time.monotonic() - t0 < 5
        assert c.get("/health").json() == {
            "instance": rt.instance,
            "ok": True,
            "version": rt.version,
        }
    finally:
        release.set()


def test_health_needs_no_cookie_and_checks_the_host(tmp_path, started):
    rt = started(tmp_path / "h", make_indexer=lambda s: FakeIndexer())
    base = f"http://127.0.0.1:{rt.port}"
    r = httpx.get(f"{base}/health", timeout=5)
    assert r.status_code == 200 and set(r.json()) == {"instance", "ok", "version"}
    r = httpx.get(f"{base}/health", headers={"Host": "evil.example"}, timeout=5)
    assert r.status_code == 421
    assert httpx.get(f"{base}/api/overview", timeout=5).status_code == 401


def test_dead_helper_starts_again(tmp_path, started):
    made = []

    def make(service):
        made.append(FakeIndexer(fail=len(made) == 0))  # the first helper dies
        return made[-1]

    rt = started(tmp_path / "h", make_indexer=make)
    assert wait_for(lambda: len(made) == 2 and rt.status()["state"] == "running")
    assert not rt._done.is_set()


def test_too_many_restarts_stop_the_app(tmp_path, started, monkeypatch):
    monkeypatch.setattr(runtime, "RESTART_LIMIT", 2)
    made = []

    def make(service):
        made.append(FakeIndexer(fail=True))
        return made[-1]

    rt = started(tmp_path / "h", make_indexer=make)
    assert wait_for(rt._done.is_set)
    assert rt.exit_code == runtime.EXIT_RESTART == 75
    assert len(made) == 3


def test_helper_with_no_sign_stops_the_app(tmp_path, started, monkeypatch):
    monkeypatch.setattr(runtime, "HEARTBEAT_LIMIT_S", 0.2)
    long_turn = threading.Event()
    # A long turn (a big scan) is not a hang: no stop while a turn runs.
    rt = started(tmp_path / "a", make_indexer=lambda s: FakeIndexer(lambda: long_turn.wait(10)))
    assert wait_for(lambda: rt._helper.in_turn)
    time.sleep(0.5)
    assert not rt._done.is_set()
    long_turn.set()

    class Stuck(FakeIndexer):
        def run(self, stop):  # the loop hangs between two turns
            stop.wait(30)

    stuck = started(tmp_path / "b", make_indexer=lambda s: Stuck())
    assert wait_for(stuck._done.is_set)
    assert stuck.exit_code == runtime.EXIT_RESTART


def test_second_runtime_on_the_same_home_is_refused(tmp_path, started):
    home = tmp_path / "h"
    started(home, make_indexer=lambda s: FakeIndexer())
    with pytest.raises(AlreadyRunning):
        AppRuntime(home, embed=False, make_indexer=lambda s: FakeIndexer()).start()
    # The developer helper (`anagram indexer`) uses indexer.lock: it is held too.
    assert lock.acquire(home / "indexer.lock") is None


def test_lock_is_free_after_a_stop(tmp_path):
    home = tmp_path / "h"
    rt = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer())
    rt.start()
    rt.stop()
    handle = lock.acquire(home / "app.lock")
    assert handle is not None
    handle.release()


def test_helper_state_change_gives_one_event(tmp_path, started):
    rt = started(tmp_path / "h", make_indexer=lambda s: FakeIndexer())
    assert wait_for(lambda: any(e["state"] == "running" for e in helper_events(rt)))
    time.sleep(0.3)  # more supervisor turns: no new event with no change
    states = [e["state"] for e in helper_events(rt)]
    assert states == ["starting", "running"]
    assert set(helper_events(rt)[-1]) == {"errors", "last_cycle_at", "since", "state"}
    rt.restart_helper()
    assert wait_for(lambda: [e["state"] for e in helper_events(rt)][-1] == "running")
    assert [e["state"] for e in helper_events(rt)][2:] == ["starting", "running"]


def test_cycle_inside_the_first_turn_is_running(tmp_path, started):
    """X4: Indexer sets `last_cycle_at` inside its first turn, and the turn
    can go on after that (status write, watch sync). The block must not show a
    cycle time with the state "starting"."""
    cycled, release = threading.Event(), threading.Event()
    indexer = FakeIndexer()

    def first_turn():
        indexer.state.last_cycle_at = time.time()
        cycled.set()
        release.wait(10)

    indexer._step = first_turn
    rt = started(tmp_path / "h", make_indexer=lambda s: indexer)
    try:
        assert cycled.wait(10)
        status = rt.status()
        assert status["last_cycle_at"] is not None
        assert status["state"] == "running"
    finally:
        release.set()


def test_task_on_ctx_tasks_runs(joined, started):
    _, home, svc = joined
    rt = started(home, service=svc, make_indexer=lambda s: FakeIndexer())
    ran = threading.Event()
    rt.ctx.tasks.add("test.task", ran.set, every_s=60)
    assert ran.wait(10)
    assert rt.ctx.runtime is rt  # routers reach the app through ctx.runtime


def test_port_is_kept_for_the_next_start(tmp_path):
    home = tmp_path / "h"
    rt = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer())
    rt.start()
    port = rt.port
    rt.stop()
    assert UIService(home).state.get("app_port") == port
    again = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer())
    again.start()
    try:
        assert again.port == port
    finally:
        again.stop()


def test_saved_port_in_use_gives_a_new_port(tmp_path):
    home = tmp_path / "h"
    rt = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer())
    rt.start()
    port = rt.port
    rt.stop()
    with bind_local(port):  # another process took the port of the last start
        again = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer())
        again.start()
        try:
            assert again.port != port
            assert httpx.get(f"http://127.0.0.1:{again.port}/health", timeout=10).json()["ok"]
        finally:
            again.stop()
    assert UIService(home).state.get("app_port") == again.port


def test_ui_server_holds_its_port_from_the_choice_to_the_start(tmp_path):
    """No launch race: the port is bound when the server is made, so no other
    process can take it before the start."""
    server = UIServer(UIService(tmp_path / "home"))
    try:
        with pytest.raises(OSError):
            bind_local(server.port)
        server.start()
        r = httpx.get(f"http://127.0.0.1:{server.port}/", timeout=10)
        assert r.status_code < 500
    finally:
        server.stop()
    with bind_local(server.port):  # the stop frees the port
        pass


def test_real_helper_indexes_through_open_client(joined, started, tmp_path):
    _, home, svc = joined
    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "a.md").write_text("# A\n\nsome text\n")
    svc.sources.add({"kind": "folder", "path": str(folder)}, refresh=False)

    def make(service):
        return Indexer(
            lambda: service.open_client(index=True),
            ready=service.joined,
            watch=False,
            ignore=(home.resolve(),),
        )

    rt = started(home, service=svc, make_indexer=make)
    assert wait_for(lambda: rt.status()["last_cycle_at"] is not None, timeout=30)
    assert rt.status()["state"] == "running"
    assert svc.sources.helper_status() is not None


# ---------------------------------------------------------------------- log


def test_redact_rules():
    home = "/Users/someone/.anagram"
    assert logs.redact(f"open {home}/vault.sqlite now", (home,)) == "open <path>"
    assert logs.redact("scan /a b/c d.pdf failed") == "scan <path>"
    assert logs.redact(r"read C:\Users\x\f.docx") == "read <path>"
    assert logs.redact("read ~/notes.md") == "read <path>"
    assert (
        logs.redact("new/changed 3, anagram/shell/ui/x.py:4")
        == "new/changed 3, anagram/shell/ui/x.py:4"
    )
    assert (
        logs.redact("GET https://host.test/api/x?path=/secret#frag done")
        == "GET https://host.test/api/x?<removed> done"
    )
    assert (
        logs.redact("go http://127.0.0.1:5/open/tok123") == "go http://127.0.0.1:5/open/<removed>"
    )
    assert logs.plain_arg("src-1a2b") == "src-1a2b" and logs.plain_arg(3) == 3
    assert logs.plain_arg("RuntimeError: bad file x.pdf") == logs.ARG_MARK


def test_log_has_no_canary(tmp_path):
    home = tmp_path / "home"
    folder = tmp_path / f"{CANARY}-folder"
    folder.mkdir(parents=True)
    bad = folder / f"{CANARY}-name.pdf"
    bad.write_text(f"content {CANARY}")
    path = logs.setup(home)
    try:
        # A scan error and a convert error, as the helper reports them.
        report = ScanReport(errors=[("src-1", f"OSError: cannot read {bad}")])

        class Jobs:
            def recover_stale(self):
                return 0

            def run(self, limit=None):
                raise ValueError(f"convert of {bad} failed: {CANARY} text in the file")

        class Idx:
            embedder = None
            jobs = Jobs()

            def scan(self, *a, **k):
                return report

            def sources(self):
                return {}

        @contextlib.contextmanager
        def session():
            yield None, Idx()

        indexer = Indexer(session, watch=False)
        with pytest.raises(ValueError):
            indexer.cycle()
        # A watch error: the code logs the source id, not the path.
        indexer._error("watch src-1", OSError(f"inotify limit for {folder}"))
        try:
            raise RuntimeError(f"job failed on {bad.name}: {CANARY}")
        except RuntimeError:
            # As local/index/local.py logs a job error: the message is an argument.
            logging.getLogger("anagram.local.index").warning(
                "%s job %d failed: %s", "convert", 7, f"RuntimeError: {CANARY}", exc_info=True
            )
            logging.getLogger("anagram.local.index").exception("discover failed for %s", folder)
        logging.getLogger("anagram.shell.ui").warning(f"direct text {folder} and {bad}")
    finally:
        logs.teardown()
    text = path.read_text()
    assert "indexer watch src-1: OSError" in text
    assert "indexer scan src-1: RuntimeError" in text
    assert "convert job 7 failed: <removed>" in text  # the message argument
    assert CANARY not in text and str(tmp_path) not in text, text
    assert path.stat().st_mode & 0o777 == 0o600


# ---------------------------------------------------------------- command


@pytest.mark.parametrize("entry", ["run_forever", "cmd_app_run"])
def test_a_stop_signal_during_the_start_stops_the_app_cleanly(tmp_path, monkeypatch, entry):
    """The server answers before `start` returns, so a launcher can send
    SIGTERM while the start goes on. The handler is set before the start:
    the app stops cleanly with exit code 0. (With the handler set after the
    start, the default action killed `app run`: exit -15 in
    `test_app_run_command_serves_health` on a busy machine.) The test sends
    the signal at a fixed point: after the start, before `run_forever`."""
    assert threading.current_thread() is threading.main_thread()
    home = tmp_path / "h"
    missed: list[int] = []
    made: list[AppRuntime] = []
    real_start = AppRuntime.start

    def start(self):
        made.append(self)
        real_start(self)
        assert httpx.get(f"http://127.0.0.1:{self.port}/health", timeout=10).json()["ok"]
        os.kill(os.getpid(), signal.SIGTERM)  # the launcher stops the app that answers

    def default_action(*_):
        missed.append(signal.SIGTERM)  # in place of the kill: this test process stays
        made[-1].request_stop()

    monkeypatch.setattr(AppRuntime, "start", start)
    monkeypatch.setattr(AppRuntime, "_default_service", lambda self: UIService(self.home))
    old = signal.signal(signal.SIGTERM, default_action)
    old_int = signal.getsignal(signal.SIGINT)
    try:
        if entry == "run_forever":
            rt = AppRuntime(home, embed=False, tick_s=0.05, make_indexer=lambda s: FakeIndexer())
            code = rt.run_forever()
        else:
            from anagram.shell.app.cli import cmd_app_run

            monkeypatch.setattr(AppRuntime, "_new_indexer", lambda self, s: FakeIndexer())
            args = type("Args", (), {"home": home, "port": 0, "no_embed": True})()
            code = cmd_app_run(args)
    finally:
        signal.signal(signal.SIGTERM, old)
        signal.signal(signal.SIGINT, old_int)
    assert missed == []  # the app's handler took the signal
    assert code == 0
    handle = lock.acquire(home / "app.lock")
    assert handle is not None  # a clean stop: the lock is free
    handle.release()
    assert not (home / "run" / "app.json").exists()


def test_app_run_command_serves_health(tmp_path):
    """The real command in a child process. The child takes a free port
    itself and names it in the runtime file: a port that this process
    chose could be taken by another process before the child binds it."""
    home = tmp_path / "home"
    env = {**os.environ, "ANAGRAM_KEYSTORE": "file", "HF_HUB_OFFLINE": "1"}
    proc = subprocess.Popen(  # noqa: S603 - this interpreter, fixed arguments
        [sys.executable, "-m", "anagram", "--home", str(home), "app", "run", "--no-embed"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=Path(__file__).parent,
    )
    try:

        def health():
            doc = control.read_runtime(home)  # written when the server is up
            if doc is None:
                assert proc.poll() is None, "app run stopped before it served"
                return None
            got = httpx.get(f"http://127.0.0.1:{doc['port']}/health", timeout=10).json()
            assert got["instance"] == doc["instance"]  # this child, not another server
            return got

        assert wait_for(lambda: health() is not None, timeout=60, step=0.2)
        assert health()["ok"] is True
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0
        assert (home / "logs" / "app.log").exists()
        assert control.read_runtime(home) is None  # a clean stop removes the file
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
