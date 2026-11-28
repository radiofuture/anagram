"""`AppRuntime`: the one Anagram process on the computer of a member.

It owns the UI service, the local UI server, the index helper thread, and the
supervisor. The background tasks of the tracks run on the task runner of the
UI context (`shell/ui/tasks.py`); the server starts and stops them.

Start order: the app lock, the log, the key migration (with the lock held),
the UI server, the helper thread, the supervisor.

The helper thread has its own client and its own index connection
(`UIService.open_client`). It does not take the UI lock, so a long scan does
not stop a UI request.

Supervisor: if the helper thread is dead, start it again (at most
`RESTART_LIMIT` times in `RESTART_WINDOW_S`). If the limit is passed, or the
helper loop gave no sign for `HEARTBEAT_LIMIT_S` while no turn runs, the
process stops with the exit code `EXIT_RESTART`. The service manager of the
operating system starts it again.
"""

from __future__ import annotations

import contextlib
import logging
import secrets
import signal
import socket
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path

import anagram
from anagram.core.timefmt import iso_or_none
from anagram.identity.api import (
    KeystoreError,
    SlotUnavailable,
    keychain_needs_migration,
    migrate_keychain_to_os,
    os_slot,
    policy,
)
from anagram.shell.app import control, lock, logs, update
from anagram.shell.ui.errors import UIError
from anagram.shell.ui.server import UIServer, bind_local
from anagram.shell.ui.service import UIService

log = logging.getLogger("anagram.shell.app")

APP_LOCK = "app.lock"
INDEXER_LOCK = "indexer.lock"  # the lock of `anagram indexer` (developers)
PORT_KEY = "app_port"
EXIT_RESTART = 75  # the service manager starts the app again
RESTART_LIMIT = 5
RESTART_WINDOW_S = 600.0
HEARTBEAT_LIMIT_S = 600.0
SUPERVISOR_TICK_S = 2.0
UPDATE_TICK_S = 3600.0  # the checker itself fetches at most one time each day
HELPER_STATES = ("starting", "running", "stopped", "error")


class AlreadyRunning(RuntimeError):
    """Another app (or a developer helper) runs for this data directory."""


class _Helper:
    """One run of the helper: an indexer, its thread, and its stop signal."""

    def __init__(self, indexer, on_exit: Callable[[], None]) -> None:
        self.indexer = indexer
        self.stop = threading.Event()
        self.turns = 0
        self.in_turn = False
        self.beat = time.monotonic()
        self.failed = False
        self._on_exit = on_exit
        step = getattr(indexer, "step", None)
        self.counted = callable(step)
        if self.counted:
            # Count the turns of the loop: the sign that the helper is alive.
            def counted():
                self.in_turn = True
                try:
                    return step()
                finally:
                    self.in_turn = False
                    self.turns += 1
                    self.beat = time.monotonic()

            indexer.step = counted
        self.thread = threading.Thread(target=self._run, name="anagram-helper", daemon=True)

    def _run(self) -> None:
        try:
            self.indexer.run(self.stop)
        except BaseException as exc:  # the supervisor starts a new helper
            self.failed = True
            log.error("helper stopped: %s", type(exc).__name__, exc_info=exc)
        finally:
            self._on_exit()

    def alive(self) -> bool:
        return self.thread.is_alive()


class AppRuntime:
    def __init__(
        self,
        home: str | Path,
        *,
        port: int | None = None,
        embed: bool = True,
        service: UIService | None = None,
        make_indexer: Callable[[UIService], object] | None = None,
        tick_s: float = SUPERVISOR_TICK_S,
        autostart=None,
        helper: bool = True,
    ) -> None:
        # `service` and `make_indexer` are for tests (a fake node, a fake helper).
        # `autostart`: the login service for `GET /api/app` (shell/app/settings.py);
        # None: the service of this system, made at the first use.
        self.autostart = autostart
        # `helper=False` (`anagram ui`): the UI only, with no index helper and
        # no supervisor. It takes the app lock and writes the runtime file,
        # so that `anagram open` finds it and one home has one UI. The
        # developer helper (`anagram indexer`) can run next to it.
        self.with_helper = helper
        self.home = Path(home)
        self.port = port
        self.embed = embed
        self.service = service
        self.version = anagram.__version__
        self.instance = secrets.token_hex(8)
        self.control = secrets.token_urlsafe(32)  # the bearer of /control/*
        self.tokens = control.OpenTokens()
        self.started_at: float | None = None
        self.server: UIServer | None = None
        self.exit_code = 0
        self._make_indexer = make_indexer or self._new_indexer
        self._tick_s = tick_s
        self._locks: list[lock.LockHandle] = []
        self._helper: _Helper | None = None
        self._helper_lock = threading.RLock()
        self._restarts: deque[float] = deque()
        self._state = "stopped"
        self._since = time.time()
        self._published: tuple | None = None
        self._wake = threading.Event()
        self._done = threading.Event()
        self._supervisor: threading.Thread | None = None
        self._started = False
        # The update check. Off (no request) when the build has no
        # manifest URL or release key (`shell/app/update.py`).
        self.updates = update.UpdateChecker(on_change=self._publish_update)

    # ------------------------------------------------------------ start, stop

    @property
    def ctx(self):
        """The UI context of the server (bus, tasks)."""
        return self.server.app.state.ctx

    def start(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._take_locks()
        try:
            logs.setup(self.home)
            self._migrate_keys()
            if self.service is None:
                self.service = self._default_service()
            self.server = UIServer(
                self.service, sock=self._bind_port(), tokens=self.tokens, runtime=self
            )
            self.port = self.server.port
            logs.setup(self.home)  # uvicorn replaced the handlers of its loggers
            control.register(self.server.app, self)
            self.server.start()  # also the bridges and ctx.tasks
            if self.updates.enabled:
                self.ctx.tasks.add("app.update", self.updates.tick, UPDATE_TICK_S)
            control.write_runtime(self.home, control.runtime_doc(self))  # the server is up
            self.started_at = time.time()
            self._started = True
            if self.with_helper:
                self._start_helper()
                self._supervisor = threading.Thread(
                    target=self._supervise, name="anagram-supervisor", daemon=True
                )
                self._supervisor.start()
            log.info("app started (version %s)", self.version)
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        """Stop the helper, the tasks, and the server. Release the lock."""
        self._done.set()
        self._wake.set()
        if self._supervisor is not None and self._supervisor is not threading.current_thread():
            self._supervisor.join(timeout=10)
        self._stop_helper()
        if self._locks:
            control.remove_runtime(self.home, self.instance)  # only our own file
        if self.server is not None and self._started:
            self.server.stop()
        elif self.server is not None:
            self.server.sock.close()  # the start failed: free the bound port
        if self._started:
            log.info("app stopped")
        self._started = False
        logs.teardown()
        for handle in self._locks:
            handle.release()
        self._locks = []

    def request_stop(self, exit_code: int = 0) -> None:
        """Ask `run_forever` to stop (a signal, the control route, the supervisor)."""
        if exit_code:
            self.exit_code = exit_code
        self._done.set()
        self._wake.set()

    def handle_signals(self) -> None:
        """SIGTERM and SIGINT ask for a clean stop. Call it before `start`:
        the server answers before `start` returns, so a launcher can send a
        stop while the start goes on. With the default action that stop
        kills the process, and the lock and the runtime file stay. Only the
        main thread can set a handler."""
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: self.request_stop())

    def run_forever(self) -> int:
        """Start, then block until a stop is asked. SIGTERM and SIGINT stop
        the app cleanly, also a stop that came during the start. Return the
        exit code."""
        self.handle_signals()
        if not self._started:
            self.start()
        try:
            while not self._done.wait(1.0):
                if self.server is not None and not self.server.thread.is_alive():
                    log.error("the UI server stopped")
                    self.exit_code = EXIT_RESTART
                    break
        finally:
            self.stop()
        return self.exit_code

    # ---------------------------------------------------------------- set-up

    def _take_locks(self) -> None:
        for name in (APP_LOCK, INDEXER_LOCK) if self.with_helper else (APP_LOCK,):
            handle = lock.acquire(self.home / name)
            if handle is None:
                for held in self._locks:
                    held.release()
                self._locks = []
                raise AlreadyRunning("Anagram already runs for this data directory.")
            self._locks.append(handle)

    def _migrate_keys(self) -> None:
        """Move plain key files into the keychain. The app lock is held, so
        no second process reads or writes the keys of this home now. A
        keychain that is absent or locked leaves the key files as they are;
        the next start tries again."""
        try:
            if policy() == "file" or not keychain_needs_migration(self.home):
                return
            out = migrate_keychain_to_os(self.home, os_slot())
            log.info("moved %d keys into the keychain", len(out["moved"]))
        except SlotUnavailable:
            return
        except KeystoreError as exc:  # also SlotLocked
            log.warning("the keys were not moved into the keychain: %s", type(exc).__name__)

    def _default_service(self) -> UIService:  # pragma: no cover - network clients
        from anagram.models.embed import FastEmbedder
        from anagram.models.ollama_client import OllamaClient
        from anagram.shell.ui.institutions import RorApi

        return UIService(
            self.home,
            institutions=RorApi(),
            ollama=OllamaClient(),
            embedder=FastEmbedder(cache_dir=self.home / "models") if self.embed else None,
        )

    def _bind_port(self) -> socket.socket:
        """Bind the port of the server: `self.port` if given; else the port
        of the last start if it is free; else a free port. The server takes
        the bound socket, so no other process can take the port before the
        start. The port is kept in the sealed UI state. With a locked keychain
        there is no state: use a free port."""
        if self.port:
            return bind_local(self.port)
        try:
            saved = self.service.state.get(PORT_KEY)
        except (UIError, KeystoreError):
            return bind_local()
        if isinstance(saved, int) and 1024 <= saved <= 65535:
            try:
                return bind_local(saved)
            except OSError:
                pass  # another process has it: take a new port
        sock = bind_local()
        try:
            self.service.state.update(**{PORT_KEY: sock.getsockname()[1]})
        except (UIError, KeystoreError):
            pass  # the next start takes a new port
        return sock

    # ---------------------------------------------------------------- helper

    def _new_indexer(self, service: UIService):
        from anagram.local.api import Indexer

        return Indexer(
            lambda: service.open_client(index=True),
            ready=service.joined,
            embedder=service.embedder if self.embed else None,
            ignore=(self.home.resolve(),),
            on_indexed=service.enclave.refresh_suggestions,
        )

    def _start_helper(self) -> None:
        with self._helper_lock:
            helper = _Helper(self._make_indexer(self.service), self._wake.set)
            self._helper = helper
            self._set_state("starting")
            self._publish()  # before the first turn can change the state
            helper.thread.start()

    def _stop_helper(self) -> None:
        with self._helper_lock:
            helper, self._helper = self._helper, None
        if helper is not None:
            helper.stop.set()
            if helper.thread is not threading.current_thread():
                helper.thread.join(timeout=15)
        self._set_state("stopped")

    def restart_helper(self) -> None:
        """Stop the helper thread and start a new one (the person asked)."""
        self._stop_helper()
        if not self._done.is_set():
            self._start_helper()

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self._since = time.time()

    def status(self) -> dict:
        """The `helper` block of `GET /api/app`."""
        with self._helper_lock:
            helper = self._helper
            indexer_state = getattr(helper.indexer, "state", None) if helper is not None else None
            if helper is not None and self._state in ("starting", "running"):
                if helper.thread.ident is not None and not helper.alive():
                    self._set_state("error")
                elif helper.turns > 0 or getattr(indexer_state, "last_cycle_at", None) is not None:
                    # A cycle that is done is a sign of work too. The indexer
                    # sets `last_cycle_at` in its first turn, before the turn
                    # ends; the block must not show a cycle and "starting".
                    self._set_state("running")
            return {
                "errors": len(getattr(indexer_state, "errors", ()) or ()),
                "last_cycle_at": iso_or_none(getattr(indexer_state, "last_cycle_at", None)),
                "since": iso_or_none(self._since),
                "state": self._state,
            }

    def update_status(self) -> dict:
        """The `update` block of `GET /api/app` (no network call)."""
        return self.updates.status()

    def _publish_update(self, status: dict) -> None:
        if self.server is not None:
            with contextlib.suppress(Exception):
                self.ctx.bus.publish("app.update", status)

    def _publish(self) -> None:
        """Publish `app.helper` when the helper block changed (a state change
        or a new cycle)."""
        status = self.status()
        key = (status["state"], status["last_cycle_at"], status["errors"])
        if key == self._published or self.server is None:
            return
        self._published = key
        with contextlib.suppress(Exception):  # a closed bus must not stop the supervisor
            self.ctx.bus.publish("app.helper", status)

    # ------------------------------------------------------------ supervisor

    def _supervise(self) -> None:
        while not self._done.is_set():
            self._wake.wait(self._tick_s)
            self._wake.clear()
            if self._done.is_set():
                break
            try:
                self._check()
            except Exception as exc:  # logged; the next turn tries again
                log.error("supervisor: %s", type(exc).__name__, exc_info=exc)

    def _check(self) -> None:
        self._publish()
        helper = self._helper
        if helper is None:
            return
        now = time.monotonic()
        if not helper.alive():
            while self._restarts and now - self._restarts[0] > RESTART_WINDOW_S:
                self._restarts.popleft()
            if len(self._restarts) >= RESTART_LIMIT:
                log.error("the helper stopped %d times; the app stops", len(self._restarts) + 1)
                self.request_stop(EXIT_RESTART)
                return
            self._restarts.append(now)
            log.warning("the helper stopped; start %d", len(self._restarts))
            self._start_helper()
        elif helper.counted and not helper.in_turn and now - helper.beat > HEARTBEAT_LIMIT_S:
            log.error("the helper gave no sign; the app stops")
            self.request_stop(EXIT_RESTART)
