"""The sync engine: it runs one contract v2 source (`connectors/sync.py`).

    result = SyncEngine(index).run(sid, report)

`Scanner.scan_source` (`scan.py`) calls it for a source that has a `sync`
method. A contract v1 source keeps the other scan path of `scan.py`.

One run:

1. Read the source state. A source that is paused, in removal, in
   `attention`, or that waits for a later time does nothing.
2. Call `sync(ctx)` and collect the changes.
3. At each `Cursor`: one transaction writes the changes that came before it
   (`Scanner.apply_item`, `apply_removed`) and the cursor. A crash loses
   at most one batch, and the source reads that batch again.
4. After a cursor, stop when the time limit is over (`more = True`: the
   helper calls again soon) or when a pause or a removal was asked. A source
   that ends by itself has no more work for now.
5. A `SourceFault` keeps the last cursor and sets the fault of the source
   (`source_state.set_fault`). Each other exception is the fault `unknown`.
   The engine does not raise for a fault of the source.

Events go to `publish(topic, data)`. The default is
`source_state.publisher(store)`, which appends rows to `source_event`.
`source.progress` comes at most one time each second, and one time at the end
of a run that changed something. The
engine does not call the UI event bus. An event holds no item name, no item
text, and no token.

A provider delete (`Delete`) marks the item as removed and deletes its chunks
and vectors. The versions and the evidence openings stay, because a
checkpoint can already commit to them.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from anagram.local.index.store import loads
from anagram.local.sources import source_state
from anagram.local.sources.base import KnownItem
from anagram.local.sources.http import SourceFault
from anagram.local.sources.sync import BATCH_MAX, Cursor, Delete, Note, SyncContext, Upsert

if TYPE_CHECKING:
    from anagram.local.index.local import LocalIndex
    from anagram.local.index.scan import ScanReport

log = logging.getLogger("anagram.local.index")

BATCH = BATCH_MAX
BUDGET_S = 45.0  # time for one source in one helper cycle
PROGRESS_EVERY_S = 1.0  # at most one `source.progress` event in this time
KEYS_PAGE = 1000
_LAST = "\U0010ffff"  # sorts after each character of a key


@dataclass
class SyncResult:
    new: int = 0
    changed: int = 0
    removed: int = 0
    more: bool = False  # the source stopped at the time limit; call again soon


class SyncEngine:
    def __init__(
        self,
        index: LocalIndex,
        *,
        publish: Callable[[str, dict], None] | None = None,
        budget_s: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.index = index
        self.store = index.store
        self.publish = publish or source_state.publisher(index.store, index.clock)
        self.budget_s = BUDGET_S if budget_s is None else budget_s
        self.monotonic = monotonic
        self._last_progress: float | None = None
        self._unpublished = False  # a commit that no progress event showed

    # ------------------------------------------------------------ context

    def _known(self, sid: str) -> Callable[[str], KnownItem | None]:
        def known(key: str) -> KnownItem | None:
            row = self.store.one(
                "SELECT digest, mtime_ns, media_type FROM item"
                " WHERE source_id = ? AND key = ? AND present = 1",
                (sid, key),
            )
            if row is None:
                return None
            digest = loads(row["digest"])
            mtime = None if row["mtime_ns"] is None else int(row["mtime_ns"])
            return KnownItem(digest, digest["size"], mtime, row["media_type"])

        return known

    def _known_keys(self, sid: str) -> Callable[[str], Iterator[str]]:
        def known_keys(prefix: str = "") -> Iterator[str]:
            after = None
            while True:
                rows = self.store.q(
                    "SELECT key FROM item WHERE source_id = ? AND present = 1"
                    " AND key >= ? AND key < ? AND (? IS NULL OR key > ?)"
                    " ORDER BY key LIMIT ?",
                    (sid, prefix, prefix + _LAST, after, after, KEYS_PAGE),
                )
                for r in rows:
                    if r["key"].startswith(prefix):
                        yield r["key"]
                if len(rows) < KEYS_PAGE:
                    return
                after = rows[-1]["key"]

        return known_keys

    def _stop(self, sid: str) -> Callable[[], bool]:
        def stop() -> bool:
            state = source_state.read(self.store, sid)
            return state is None or state.paused or state.stored_status == source_state.REMOVING

        return stop

    # ---------------------------------------------------------------- run

    def run(self, sid: str, report: ScanReport) -> SyncResult:
        index = self.index
        result = SyncResult()
        state = source_state.get(self.store, sid, index.clock())
        if not state.due(index.clock()):
            return result
        src = index.source(sid)
        stop = self._stop(sid)
        deadline = self.monotonic() + self.budget_s
        ctx = SyncContext(
            state=state.cursor,
            known=self._known(sid),
            known_keys=self._known_keys(sid),
            deadline=deadline,
            stop=stop,
        )
        pending: list[Upsert | Delete] = []
        note: Note | None = None
        fault: tuple[str, str, float | None] | None = None
        stopped = False
        changes = None
        try:
            conn = index.connector(sid)
            changes = conn.sync(ctx)
            for change in changes:
                if isinstance(change, Note):
                    note = _merge(note, change)
                elif isinstance(change, Cursor):
                    self._commit(sid, src, pending, change.state, note, result, report)
                    pending, note = [], None
                    self._progress(sid, result)
                    if stop():
                        stopped = True
                        break
                    if self.monotonic() > deadline:
                        result.more = True
                        break
                elif isinstance(change, Upsert | Delete):
                    pending.append(change)
                    if len(pending) >= BATCH:
                        # A source that gives no cursor in time: keep memory
                        # small. The cursor stays, so a crash reads these
                        # changes again, and they change nothing then.
                        self._commit(sid, src, pending, None, note, result, report)
                        pending, note = [], None
                else:
                    raise TypeError(f"a source gave {type(change).__name__}, not a change")
            else:
                if pending or note is not None:
                    self._commit(sid, src, pending, None, note, result, report)
        except SourceFault as exc:
            fault = (exc.code, exc.detail, exc.retry_at)
        except Exception as exc:  # one bad source must not stop the rest
            # The class name only: an exception text can hold a URL or item text.
            log.warning("sync of a source failed: %s", type(exc).__name__, exc_info=True)
            fault = ("unknown", type(exc).__name__, None)
        finally:
            close = getattr(changes, "close", None)
            if callable(close):
                close()
        self._end(sid, result, fault, stopped)
        return result

    # -------------------------------------------------------------- write

    def _commit(
        self,
        sid: str,
        src: dict,
        pending: list[Upsert | Delete],
        cursor: dict | None,
        note: Note | None,
        result: SyncResult,
        report: ScanReport,
    ) -> None:
        """One transaction: the changes, then the cursor and the progress."""
        index = self.index
        now, t = index.now(), index.clock()
        kind = src["config"]["kind"]
        before = (len(report.new), len(report.changed), len(report.removed))
        new_items: list[int] = []
        with self.store.transaction():
            for change in pending:
                if isinstance(change, Upsert):
                    prev = self.store.one(
                        "SELECT * FROM item WHERE source_id = ? AND key = ?",
                        (sid, change.item.key),
                    )
                    item_id = index.scanner.apply_item(sid, kind, change.item, prev, now, t, report)
                    if item_id is not None:
                        new_items.append(item_id)
                else:
                    for row in self._delete_rows(sid, change):
                        index.scanner.apply_removed(sid, row["id"], row["key"], now, report)
                        self._drop_text(row["id"])
            if new_items:
                index.scanner.project_relations(sid, src["config"], new_items, now)
            if cursor is not None:
                source_state.set_cursor(self.store, sid, cursor, now=t)
            if note is not None:
                source_state.set_progress(
                    self.store,
                    sid,
                    now=t,
                    phase=note.phase,
                    total=note.total,
                    done=note.done,
                    at=note.at,
                    skipped=note.skipped or None,
                )
            new = len(report.new) - before[0]
            changed = len(report.changed) - before[1]
            removed = len(report.removed) - before[2]
            if new or changed or removed:
                self.store.x("UPDATE source SET last_change_at = ? WHERE id = ?", (now, sid))
        # After the commit: a transaction that fails must not count.
        self._unpublished = True
        result.new += new
        result.changed += changed
        result.removed += removed

    def _delete_rows(self, sid: str, change: Delete) -> list:
        if not change.prefix:
            return self.store.q(
                "SELECT id, key FROM item WHERE source_id = ? AND key = ? AND present = 1",
                (sid, change.key),
            )
        rows = self.store.q(
            "SELECT id, key FROM item WHERE source_id = ? AND present = 1"
            " AND key >= ? AND key < ? ORDER BY key",
            (sid, change.key, change.key + _LAST),
        )
        return [r for r in rows if r["key"].startswith(change.key)]

    def _drop_text(self, item_id: int) -> None:
        """Delete the chunks, the vectors, and the waiting jobs of an item
        that the provider deleted."""
        for row in self.store.q("SELECT id FROM version WHERE item_id = ?", (item_id,)):
            self.index.jobs.drop_chunks(row["id"])
            self.store.x("DELETE FROM job WHERE version_id = ? AND state = 'queued'", (row["id"],))

    # -------------------------------------------------------------- events

    def _progress(self, sid: str, result: SyncResult, *, force: bool = False) -> None:
        """Publish `source.progress`, at most one time in `PROGRESS_EVERY_S`."""
        t = self.monotonic()
        if (
            not force
            and self._last_progress is not None
            and t - self._last_progress < PROGRESS_EVERY_S
        ):
            return
        self._last_progress = t
        self._unpublished = False
        state = source_state.read(self.store, sid)
        if state is None:
            return
        counts = self.index.jobs.progress_counts(sid)
        self.publish(
            "source.progress",
            {
                "at": state.at,
                "changed": result.changed,
                "converting": counts["converting"],
                "done": state.done,
                "embedding": counts["embedding"],
                "id": sid,
                "indexed": counts["indexed"],
                "new": result.new,
                "phase": state.phase,
                "removed": result.removed,
                "total": state.total,
            },
        )

    def _end(
        self,
        sid: str,
        result: SyncResult,
        fault: tuple[str, str, float | None] | None,
        stopped: bool,
    ) -> None:
        index = self.index
        t = index.clock()
        state = source_state.read(self.store, sid)
        if state is None or state.stored_status == source_state.REMOVING:
            return  # removal owns the source now
        if fault is not None:
            code, detail, retry_at = fault
            source_state.set_fault(
                self.store, sid, code, detail, now=t, retry_at=retry_at, publish=self.publish
            )
        else:
            index.scanner.mark_scanned(sid, index.now(), False)
            first = state.phase == source_state.FIRST_SYNC or (
                state.phase is None
                and state.stored_status == source_state.FIRST_SYNC
                and (result.more or stopped)
            )
            source_state.set_status(
                self.store,
                sid,
                source_state.FIRST_SYNC if first else source_state.LIVE,
                now=t,
                publish=self.publish,
            )
        if self._unpublished:
            self._progress(sid, result, force=True)


def _merge(old: Note | None, new: Note) -> Note:
    """The newest value of each field."""
    if old is None:
        return new
    return Note(
        phase=new.phase if new.phase is not None else old.phase,
        total=new.total if new.total is not None else old.total,
        done=new.done if new.done is not None else old.done,
        at=new.at if new.at is not None else old.at,
        skipped=new.skipped or old.skipped,
    )
