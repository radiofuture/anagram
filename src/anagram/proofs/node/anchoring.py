"""Background anchoring of checkpoints (RFC 3161 TSAs, OpenTimestamps).

A commit never waits for a network anchor. The node publishes a cosigned
checkpoint at once. This scheduler then anchors checkpoints in batches:

1. Batch. At most once in `batch_seconds`, if the log grew, the scheduler makes
   one job for each anchor over the newest checkpoint. That checkpoint includes
   all earlier entries, so one anchor covers the whole batch.
2. Stamp. A due job calls `anchor.stamp(digest)`. A failure is logged and the
   job tries again later (exponential backoff, at most `retry_max` seconds).
   The job never stops; a newer successful job of the same anchor makes older
   open jobs "superseded".
3. Upgrade. An OpenTimestamps record is first only "pending". The scheduler
   asks the calendars again each `upgrade_seconds` until the record has a
   Bitcoin attestation.

Each success writes the records into the checkpoint row of the log store
(`SQLiteLog.set_checkpoint_anchors`). Clients get them with
`GET /log/anchored?size=N` and update their proof bundles
(`Client.findings.refresh_anchors`).

Job state is in `<node>/anchors.sqlite`.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path

from anagram.core.shared_db import SharedDB
from anagram.proofs.anchors.base import Anchor
from anagram.proofs.anchors.ots import is_complete
from anagram.proofs.log.checkpoint import Checkpoint
from anagram.proofs.log.store import SQLiteLog

log = logging.getLogger("anagram.proofs.anchors")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    size INTEGER NOT NULL, spec TEXT NOT NULL, status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL,
    last_error TEXT, record TEXT, done_at INTEGER,
    PRIMARY KEY (size, spec));
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""

# Job status values.
OPEN = "open"  # waiting for a stamp (first try or a retry)
UPGRADING = "upgrading"  # stamped; OpenTimestamps record not complete yet
DONE = "done"
SUPERSEDED = "superseded"  # a newer checkpoint got this anchor first


class AnchorScheduler:
    def __init__(
        self,
        store: SQLiteLog,
        origin: str,
        anchors: dict[str, Anchor],
        db_path: str | Path,
        *,
        batch_seconds: int = 600,
        retry_base: int = 60,
        retry_max: int = 3600,
        upgrade_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.origin = origin
        self.anchors = dict(anchors)
        self.batch_seconds = batch_seconds
        self.retry_base = retry_base
        self.retry_max = retry_max
        self.upgrade_seconds = upgrade_seconds
        self.clock = clock
        self._lock = threading.RLock()
        self._db = SharedDB(db_path)
        self._db.executescript(_SCHEMA)

    # ------------------------------------------------------------- helpers

    def now(self) -> int:
        return int(self.clock())

    def _get(self, key: str) -> int:
        row = self._db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return int(row[0]) if row else 0

    def _set(self, key: str, value: int) -> None:
        self._db.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (key, value))

    def _digest(self, size: int) -> bytes:
        return Checkpoint(self.origin, size, self.store.root(size)).digest()

    def _backoff(self, attempts: int) -> int:
        return min(self.retry_base * (2 ** max(attempts - 1, 0)), self.retry_max)

    def _write_checkpoint(self, size: int) -> None:
        """Put the inline records (fake) and the background records of `size`
        into the checkpoint row."""
        row = self.store.checkpoint_at(size)
        if row is None:
            return
        keep = [r for r in json.loads(row[1]) if r.get("type") == "fake"]
        records = [
            json.loads(rec)
            for (rec,) in self._db.execute(
                "SELECT record FROM jobs WHERE size = ? AND record IS NOT NULL ORDER BY spec",
                (size,),
            )
        ]
        self.store.set_checkpoint_anchors(size, json.dumps(keep + records))

    # --------------------------------------------------------------- steps

    def batch(self) -> int | None:
        """Make jobs for the newest checkpoint if one is due. Return its size."""
        if not self.anchors:
            return None
        latest = self.store.latest_checkpoint()
        if latest is None:
            return None
        size = latest[0]
        now = self.now()
        with self._lock:
            if size <= self._get("batch_size"):
                return None
            if now - self._get("batch_time") < self.batch_seconds:
                return None
            for spec in self.anchors:
                self._db.execute(
                    "INSERT OR IGNORE INTO jobs (size, spec, status, next_try) VALUES (?, ?, ?, ?)",
                    (size, spec, OPEN, now),
                )
            self._set("batch_size", size)
            self._set("batch_time", now)
        log.info("anchor batch: checkpoint %d, %d anchor(s)", size, len(self.anchors))
        return size

    def _due(self, status: str) -> list[tuple[int, str, int, str | None]]:
        return [
            (int(r[0]), r[1], int(r[2]), r[3])
            for r in self._db.execute(
                "SELECT size, spec, attempts, record FROM jobs WHERE status = ? AND next_try <= ?"
                " ORDER BY size, spec",
                (status, self.now()),
            )
        ]

    def stamp_due(self) -> None:
        for size, spec, attempts, _ in self._due(OPEN):
            anchor = self.anchors.get(spec)
            if anchor is None:
                continue  # the anchor was removed from the config
            try:
                record = anchor.stamp(self._digest(size))
            except Exception as exc:  # any failure: log and try again
                wait = self._backoff(attempts + 1)
                self._db.execute(
                    "UPDATE jobs SET attempts = ?, next_try = ?, last_error = ?"
                    " WHERE size = ? AND spec = ?",
                    (attempts + 1, self.now() + wait, str(exc)[:500], size, spec),
                )
                log.warning(
                    "anchor %s failed for checkpoint %d (attempt %d): %s; next try in %d s",
                    spec,
                    size,
                    attempts + 1,
                    exc,
                    wait,
                )
                continue
            pending = record.get("type") == "opentimestamps" and not is_complete(record)
            status = UPGRADING if pending else DONE
            with self._lock:
                self._db.execute(
                    "UPDATE jobs SET status = ?, attempts = ?, record = ?, last_error = NULL,"
                    " next_try = ?, done_at = ? WHERE size = ? AND spec = ?",
                    (
                        status,
                        attempts + 1,
                        json.dumps(record),
                        self.now() + self.upgrade_seconds,
                        self.now(),
                        size,
                        spec,
                    ),
                )
                self._db.execute(
                    "UPDATE jobs SET status = ? WHERE spec = ? AND size < ? AND status = ?",
                    (SUPERSEDED, spec, size, OPEN),
                )
                self._write_checkpoint(size)
            log.info("anchor %s done for checkpoint %d (%s)", spec, size, status)

    def upgrade_due(self) -> None:
        for size, spec, _attempts, record in self._due(UPGRADING):
            anchor = self.anchors.get(spec)
            upgrade = getattr(anchor, "upgrade", None)
            if upgrade is None or record is None:
                continue
            try:
                new = upgrade(json.loads(record))
            except Exception as exc:  # an anchor service can fail in many ways; logged
                log.warning("anchor upgrade %s failed for checkpoint %d: %s", spec, size, exc)
                new = None
            done = new is not None and is_complete(new)
            with self._lock:
                self._db.execute(
                    "UPDATE jobs SET status = ?, record = ?, next_try = ? WHERE size = ? AND spec = ?",
                    (
                        DONE if done else UPGRADING,
                        json.dumps(new) if new is not None else record,
                        self.now() + self.upgrade_seconds,
                        size,
                        spec,
                    ),
                )
                if new is not None:
                    self._write_checkpoint(size)
            if done:
                log.info("anchor %s complete for checkpoint %d", spec, size)

    def run_once(self) -> None:
        self.batch()
        self.stamp_due()
        self.upgrade_due()

    def start(self, every: float = 5.0) -> threading.Event:
        """Run in a background thread. Set the returned event to stop."""
        stop = threading.Event()

        def run() -> None:
            while not stop.wait(every):
                try:
                    self.run_once()
                except Exception:  # keep the thread alive
                    log.exception("anchor scheduler step failed; trying again")

        threading.Thread(target=run, daemon=True, name="anagram-anchors").start()
        return stop

    # --------------------------------------------------------------- reads

    def anchored(self, min_size: int) -> dict | None:
        """The first checkpoint at or after `min_size` with a background anchor."""
        row = self._db.execute(
            "SELECT MIN(size) FROM jobs WHERE size >= ? AND status IN (?, ?)",
            (min_size, UPGRADING, DONE),
        ).fetchone()
        if row is None or row[0] is None:
            return None
        size = int(row[0])
        note, anchors = self.store.checkpoint_at(size)
        return {"anchors": json.loads(anchors), "checkpoint": note, "tree_size": size}

    def status(self) -> dict:
        """Counts and the last error, for the admin page (no user data)."""
        counts = {
            s: int(n)
            for s, n in self._db.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status")
        }
        last = self._db.execute(
            "SELECT MAX(size) FROM jobs WHERE status IN (?, ?)", (UPGRADING, DONE)
        ).fetchone()[0]
        err = self._db.execute(
            "SELECT spec, last_error FROM jobs WHERE status = ? AND last_error IS NOT NULL"
            " ORDER BY size DESC LIMIT 1",
            (OPEN,),
        ).fetchone()
        return {
            "anchors": sorted(self.anchors),
            "counts": counts,
            "last_anchored_size": last,
            "last_error": f"{err[0]}: {err[1]}" if err else None,
        }
