"""Background tasks of the app process.

A track that needs periodic work adds a task in its router module:

    ctx.tasks.add("shares.sync", sync, every_s=900)

The track does not start a thread. The process that hosts the UI (`anagram
app run`, or `anagram ui` for developers) calls `start` one time and `stop` at
the end. Each task has one daemon thread. A task does not run before the
member has joined a node. A task that fails logs the error class and the task
name (not the message: a message can hold a path or a name), waits `every_s`,
and runs again.

A task gets its client with `UIService.open_client(index=...)`, not with
`service.session()`, so that it does not hold the UI lock while it works.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

log = logging.getLogger("anagram.shell.ui.tasks")
READY_POLL_S = 1.0


class TaskRunner:
    def __init__(
        self, ready: Callable[[], bool] | None = None, *, ready_poll_s: float = READY_POLL_S
    ) -> None:
        # `ready`: `service.joined`. None: the tasks run at once.
        self._ready = ready or (lambda: True)
        self._ready_poll_s = ready_poll_s
        self._lock = threading.Lock()
        self._tasks: dict[str, tuple[Callable[[], None], float | Callable[[], float]]] = {}
        self._on_stop: dict[str, Callable[[], None]] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._stop = threading.Event()
        self._started = False

    def add(
        self,
        name: str,
        fn: Callable[[], None],
        every_s: float | Callable[[], float],
        *,
        on_stop: Callable[[], None] | None = None,
    ) -> None:
        """Register a task. `every_s` is the wait between two runs, in
        seconds; a callable is asked before each wait. `on_stop`, if given,
        runs when `stop()` is called to cancel any blocking work."""
        if not isinstance(name, str) or not name:
            raise ValueError("a task needs a name")
        if not callable(every_s) and every_s <= 0:
            raise ValueError("every_s must be more than 0")
        with self._lock:
            if name in self._tasks:
                raise ValueError(f"the task {name} exists")
            self._tasks[name] = (fn, every_s)
            if on_stop is not None:
                self._on_stop[name] = on_stop
            if self._started and not self._stop.is_set():
                self._spawn(name)

    def start(self) -> None:
        """Start one daemon thread for each task. A second call does nothing."""
        with self._lock:
            if self._started:
                return
            self._started = True
            for name in self._tasks:
                self._spawn(name)

    def signal_stop(self) -> None:
        """Signal all tasks to stop and invoke their cancel hooks."""
        self._stop.set()
        with self._lock:
            hooks = list(self._on_stop.values())
        for hook in hooks:
            try:
                hook()
            except Exception as exc:  # best-effort cancel hook
                log.debug("task stop hook failed: %s", type(exc).__name__)

    def join(self, timeout: float = 5.0) -> None:
        """Wait for all task threads to exit, sharing `timeout` across them."""
        with self._lock:
            threads = list(self._threads.values())
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def stop(self) -> None:
        """Stop all tasks. Cancel hooks interrupt blocking calls."""
        self.signal_stop()
        self.join()

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._tasks)

    # ------------------------------------------------------------ internal

    def _spawn(self, name: str) -> None:
        thread = threading.Thread(target=self._loop, args=(name,), name=f"task:{name}", daemon=True)
        self._threads[name] = thread
        thread.start()

    def _loop(self, name: str) -> None:
        fn, every_s = self._tasks[name]
        while not self._stop.is_set():
            try:
                if not self._ready():
                    self._stop.wait(self._ready_poll_s)
                    continue
                fn()
            except Exception as exc:  # logged; the task runs again
                if self._stop.is_set():
                    break
                log.error("task %s failed: %s", name, type(exc).__name__)
            if self._stop.is_set():
                break
            try:
                wait = float(every_s() if callable(every_s) else every_s)
            except Exception as exc:  # logged; the next turn uses 60 s
                log.error("task %s has no interval: %s", name, type(exc).__name__)
                wait = 60.0
            self._stop.wait(max(wait, 0.01))
