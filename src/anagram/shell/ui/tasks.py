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
        self._threads: dict[str, threading.Thread] = {}
        self._stop = threading.Event()
        self._started = False

    def add(self, name: str, fn: Callable[[], None], every_s: float | Callable[[], float]) -> None:
        """Register a task. `every_s` is the wait between two runs, in
        seconds; a callable is asked before each wait."""
        if not isinstance(name, str) or not name:
            raise ValueError("a task needs a name")
        if not callable(every_s) and every_s <= 0:
            raise ValueError("every_s must be more than 0")
        with self._lock:
            if name in self._tasks:
                raise ValueError(f"the task {name} exists")
            self._tasks[name] = (fn, every_s)
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

    def stop(self) -> None:
        """Stop all tasks. A task that runs now completes its turn."""
        self._stop.set()
        with self._lock:
            threads = list(self._threads.values())
        for thread in threads:
            thread.join(timeout=5)

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
                log.error("task %s failed: %s", name, type(exc).__name__)
            try:
                wait = float(every_s() if callable(every_s) else every_s)
            except Exception as exc:  # logged; the next turn uses 60 s
                log.error("task %s has no interval: %s", name, type(exc).__name__)
                wait = 60.0
            self._stop.wait(max(wait, 0.01))
