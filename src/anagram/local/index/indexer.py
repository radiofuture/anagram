"""The background indexing helper: `anagram indexer`.

It runs the index pipeline with no UI:

- Watch: local folders, Obsidian vaults, Git repositories, and Zotero export files with
  watchdog (file system events). A change marks its source; the helper scans
  that source after `DEBOUNCE_S` with no new events.
- Poll: a scan of all sources every `poll_s` (default 15 minutes), for
  sources with no events (API sources, network drives).
- Nightly: a full scan once a day after `nightly_hour` (local time). A full
  scan hashes each file again.
- Jobs: convert, enrich, embed, in small batches, so the UI can use the
  index between batches.
- Checkpoints: `checkpoint_due(source, checkpoint_s)` (default hourly), not
  after each scan. Evidence never waits for conversion.
- Start: the first cycle puts each job that a stopped process left
  `running` for more than `jobs.STALE_S` back in the queue.

Status goes into the index store (`status` table, key `indexer`). The UI reads
it. Each error is logged (`anagram.local.index` logger) and kept in the status (the
last `MAX_ERRORS`). Nothing is dropped silently.

Install as a login item (launchd, systemd) is a later step.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from anagram.core.timefmt import iso_or_none
from anagram.local.index.local import LocalIndex
from anagram.local.ports import LocalClient
from anagram.local.sources.folder import IGNORED_DIRS
from anagram.local.sources.obsidian import VAULT_IGNORED
from anagram.local.understanding import understand
from anagram.models.embed import Embedder

log = logging.getLogger("anagram.local.index")

POLL_S = 15 * 60
CHECKPOINT_S = 3600
NIGHTLY_HOUR = 3
DEBOUNCE_S = 5.0
TICK_S = 1.0
JOB_BATCH = 20
HEARTBEAT_S = 60.0
MAX_ERRORS = 20
STATUS_KEY = "indexer"
# A change inside one of these folders marks no source. `.git` is not here:
# the Git source reads it.
WATCH_IGNORED = (IGNORED_DIRS - {".git"}) | VAULT_IGNORED

# open_session() -> context manager of (client or None, LocalIndex). A None
# client means: index, but do not checkpoint (not joined yet).
SessionFactory = Callable[[], AbstractContextManager[tuple[LocalClient | None, LocalIndex]]]


def watch_paths(cfg: dict) -> list[Path]:
    """The local paths of a source config that the helper can watch."""
    kind = cfg.get("kind")
    if kind in ("folder", "obsidian"):
        return [Path(cfg["root"])]
    if kind == "git":
        return [Path(cfg["repo"])]
    if kind == "zotero_file":
        return [Path(cfg["path"]).parent]
    return []


@dataclass
class IndexerState:
    started_at: float
    last_cycle_at: float | None = None
    last_poll_at: float | None = None
    last_full_scan_at: float | None = None
    last_full_scan_day: str | None = None
    errors: list[dict] = field(default_factory=list)


class Indexer:
    def __init__(
        self,
        open_session: SessionFactory,
        *,
        ready: Callable[[], bool] = lambda: True,
        embedder: Embedder | None = None,
        poll_s: float = POLL_S,
        checkpoint_s: int = CHECKPOINT_S,
        nightly_hour: int = NIGHTLY_HOUR,
        watch: bool = True,
        ignore: tuple[Path, ...] = (),
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.open_session = open_session
        self.ready = ready
        self.embedder = embedder
        self.poll_s = poll_s
        self.checkpoint_s = checkpoint_s
        self.nightly_hour = nightly_hour
        self.watch = watch
        # Paths whose events never mark a source (the data directory: the
        # helper's own writes must not start a new scan).
        self.ignore = tuple(Path(p).resolve() for p in ignore)
        self.clock = clock
        self.state = IndexerState(started_at=clock())
        self._dirty: dict[str, float] = {}  # source id -> time of the last event
        self._dirty_lock = threading.Lock()
        self._observer = None
        self._watched: dict[str, list[Path]] = {}
        self._last_heartbeat = 0.0
        self._recovered = False  # stale jobs of a stopped process: once at start

    # ------------------------------------------------------------- errors

    def _error(self, where: str, exc: BaseException) -> None:
        msg = f"{type(exc).__name__}: {exc}"
        # The log line has the error class and an id, not the message: a
        # message can hold a path or a file name. The status keeps the message.
        step, _, ident = where.partition(" ")  # "scan src-1": the step and the source id
        log.error("indexer %s %s: %s", step, ident, type(exc).__name__, exc_info=exc)
        self.state.errors.append({"at": iso_or_none(self.clock()), "message": msg, "where": where})
        del self.state.errors[:-MAX_ERRORS]

    # -------------------------------------------------------------- cycle

    def cycle(
        self, sources: list[str] | None = None, *, full: bool = False, jobs: int | None = JOB_BATCH
    ) -> dict:
        """One scan (all sources or some), the checkpoints that are due, and
        one batch of jobs. Return what happened."""
        out = {"checkpoints": 0, "jobs": 0, "new": 0, "changed": 0, "removed": 0}
        with self.open_session() as (client, idx):
            if not self._recovered:
                # A job that a stopped process left `running` goes back to
                # `queued` (jobs.STALE_S). Only at start: no job of this
                # process runs yet.
                n = idx.jobs.recover_stale()
                if n:
                    log.info("indexer: %d stale jobs queued again", n)
                self._recovered = True
            idx.embedder = self.embedder
            report = idx.scan(sources, process=False, full=full)
            out.update(
                new=len(report.new), changed=len(report.changed), removed=len(report.removed)
            )
            for sid, msg in report.errors:
                self._error(f"scan {sid}", RuntimeError(msg))
            for sid in report.more:
                # A contract v2 source stopped at its time limit. Scan it
                # again after `DEBOUNCE_S`; the job batch runs between.
                self.mark(sid)
            if client is not None:
                for sid in sorted(idx.sources()):
                    try:
                        if idx.streams.checkpoint_due(sid, self.checkpoint_s):
                            idx.streams.checkpoint(client, sid)
                            out["checkpoints"] += 1
                    except Exception as exc:  # logged; next cycle tries again
                        self._error(f"checkpoint {sid}", exc)
            done = idx.jobs.run(limit=jobs)
            out["jobs"] = done.done + done.skipped
            self.state.last_cycle_at = self.clock()
            self._write_status(idx)
        return out

    def work(self, jobs: int = JOB_BATCH) -> int:
        """One batch of jobs with no scan. Return the number of jobs run."""
        with self.open_session() as (client, idx):
            idx.embedder = self.embedder
            done = idx.jobs.run(limit=jobs)
            if done.done + done.skipped + done.retry < jobs:  # then a few model jobs
                understand.work(client, idx, publish=getattr(self, "publish", None))
            if done.done + done.skipped + done.retry:
                self._write_status(idx)
            return done.done + done.skipped

    def status(self, idx: LocalIndex) -> dict:
        sources = []
        for sid, src in sorted(idx.sources().items()):
            sources.append(
                {
                    "id": sid,
                    "label": src["label"],
                    "kind": src["kind"],
                    "last_change_at": src["last_change_at"],
                    "last_scan_at": src["last_scan_at"],
                    "waiting": len(src["pending"]),
                    "watched": sid in self._watched,
                    **idx.jobs.progress(sid),
                }
            )
        return {
            "errors": list(self.state.errors),
            "last_cycle_at": iso_or_none(self.state.last_cycle_at),
            "last_full_scan_at": iso_or_none(self.state.last_full_scan_at),
            "next_poll_at": iso_or_none((self.state.last_poll_at or self.clock()) + self.poll_s),
            "pid": os.getpid(),
            "sources": sources,
            "started_at": iso_or_none(self.state.started_at),
            "watching": sum(len(p) for p in self._watched.values()),
        }

    def _write_status(self, idx: LocalIndex) -> None:
        idx.set_status(STATUS_KEY, self.status(idx))
        self._last_heartbeat = self.clock()

    # ------------------------------------------------------------ watching

    def mark(self, sid: str) -> None:
        with self._dirty_lock:
            self._dirty[sid] = self.clock()

    def take_dirty(self, debounce: float = DEBOUNCE_S) -> list[str]:
        now = self.clock()
        with self._dirty_lock:
            ready = sorted(s for s, t in self._dirty.items() if now - t >= debounce)
            for s in ready:
                del self._dirty[s]
        return ready

    def _sync_watches(self, idx: LocalIndex) -> None:
        if not self.watch:
            return
        want = {
            sid: [p for p in watch_paths(src["config"]) if p.is_dir()]
            for sid, src in idx.sources().items()
        }
        want = {k: v for k, v in want.items() if v}
        if want == self._watched and self._observer is not None:
            return
        self._stop_observer()
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError as exc:
            self._error("watch", exc)
            return
        indexer = self

        class Handler(FileSystemEventHandler):
            def __init__(self, sid: str) -> None:
                self.sid = sid

            def on_any_event(self, event) -> None:
                path = str(getattr(event, "src_path", ""))
                parts = set(Path(path).parts)
                if event.event_type in ("opened", "closed_no_write"):
                    return
                if parts & WATCH_IGNORED:
                    return
                if any(Path(path).is_relative_to(p) for p in indexer.ignore):
                    return
                indexer.mark(self.sid)

        obs = Observer()
        for sid, paths in want.items():
            for p in paths:
                try:
                    obs.schedule(Handler(sid), str(p), recursive=True)
                except Exception as exc:  # one bad path must not stop the rest
                    self._error(f"watch {sid}", exc)  # the source id, not the path
        obs.daemon = True
        obs.start()
        self._observer = obs
        self._watched = want

    def _stop_observer(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            with contextlib.suppress(RuntimeError):
                self._observer.join(timeout=5)
            self._observer = None
            self._watched = {}

    # ----------------------------------------------------------------- loop

    def _nightly_due(self) -> bool:
        now = datetime.fromtimestamp(self.clock())  # local time
        day = now.strftime("%Y-%m-%d")
        return now.hour >= self.nightly_hour and self.state.last_full_scan_day != day

    def step(self) -> str | None:
        """One turn of the loop. Return what it did (for tests and logs)."""
        if not self.ready():
            return None
        now = self.clock()
        if self._nightly_due():
            before = (self.state.last_full_scan_at, self.state.last_full_scan_day)
            self.state.last_full_scan_at = now
            self.state.last_full_scan_day = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
            try:
                self.cycle(full=True)
            except Exception:  # undo the scan time, then raise it again
                self.state.last_full_scan_at, self.state.last_full_scan_day = before
                raise
            self.state.last_poll_at = now
            return "full"
        if self.state.last_poll_at is None or now - self.state.last_poll_at >= self.poll_s:
            self.cycle()
            self.state.last_poll_at = now
            with self.open_session() as (_, idx):
                self._sync_watches(idx)
            return "poll"
        dirty = self.take_dirty()
        if dirty:
            self.cycle(dirty)
            return "watch"
        if self.work():
            return "jobs"
        if now - self._last_heartbeat >= HEARTBEAT_S:
            with self.open_session() as (_, idx):
                self._write_status(idx)
            return "heartbeat"
        return None

    def run(self, stop: threading.Event, tick: float = TICK_S) -> None:
        log.info("anagram indexer started (pid %d)", os.getpid())
        try:
            while not stop.is_set():
                try:
                    did = self.step()
                except Exception as exc:  # logged; the loop goes on
                    self._error("loop", exc)
                    did = None
                if did in (None, "heartbeat"):
                    stop.wait(tick)
        finally:
            self._stop_observer()
            log.info("anagram indexer stopped")


def helper_running(status: dict | None, now: float, within: float = 3 * HEARTBEAT_S) -> bool:
    """True if a helper wrote its status recently."""
    return bool(status) and now - float(status.get("updated_at", 0)) <= within
