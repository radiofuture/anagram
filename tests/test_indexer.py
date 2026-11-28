"""The background helper (`anagram indexer`): poll, watch, nightly full scan,
checkpoint cadence, status, and logged errors. No network, no model."""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager

import pytest

from anagram.local.index import jobs
from anagram.local.index.indexer import STATUS_KEY, Indexer, helper_running
from anagram.local.index.local import LocalIndex
from anagram.local.sources import FolderConnector, ZoteroFileConnector
from anagram.models.embed import FakeEmbedder
from anagram.shell.client import Client

pytestmark = pytest.mark.usefixtures("no_network")


class Clock:
    def __init__(self, t: float = 1_790_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    client = Client.init(tmp_path / "home", clock=clock)
    root = tmp_path / "lab"
    root.mkdir()
    (root / "notes.md").write_text("# Notes\n\nWe need cryo-EM time.\n")
    idx = LocalIndex.for_client(client, clock=clock)
    sid = idx.add_source(FolderConnector(root))
    idx.close()

    @contextmanager
    def open_session():
        index = LocalIndex.for_client(client, clock=clock)
        try:
            yield client, index
        finally:
            index.close()

    return client, open_session, sid, root, clock


def _status(open_session) -> dict:
    with open_session() as (_, idx):
        return idx.get_status(STATUS_KEY)


def test_poll_checkpoints_on_cadence_and_writes_status(setup):
    client, open_session, sid, root, clock = setup
    indexer = Indexer(
        open_session,
        embedder=FakeEmbedder(),
        poll_s=900,
        nightly_hour=24,
        watch=False,
        clock=clock,
    )
    assert indexer.step() == "poll"
    st = _status(open_session)
    src = st["sources"][0]
    assert src["total"] == 1 and src["indexed"] == 1 and src["waiting"] == 0
    with open_session() as (_, idx):
        assert len(idx.streams.checkpoints(sid)) == 1  # the first checkpoint is due at once
        idx.embedder = FakeEmbedder()
        assert idx.search("cryo")[0].via == ("text", "vector")
    assert helper_running(st, clock())
    assert not helper_running(st, clock() + 3600)

    # A new file: the watch marks the source; the scan runs after the debounce.
    (root / "more.md").write_text("# More\n\nWe offer beam time.\n")
    indexer.mark(sid)
    assert indexer.step() is None  # debounce
    clock.t += 6
    assert indexer.step() == "watch"
    st = _status(open_session)
    assert st["sources"][0]["total"] == 2
    assert st["sources"][0]["waiting"] == 1  # evidence pending; checkpoint not due yet
    clock.t += 3600
    assert indexer.step() == "poll"
    with open_session() as (_, idx):
        assert len(idx.streams.checkpoints(sid)) == 2 and idx.streams.pending(sid) == []


def test_start_queues_the_jobs_of_a_stopped_process_again(setup):
    """A job left `running` by a crash goes back to `queued` after STALE_S
    when the indexer starts. A newer `running` job stays: its process can
    still run."""
    client, open_session, sid, root, clock = setup
    (root / "more.md").write_text("# More\n\nWe offer beam time.\n")
    with open_session() as (_, idx):
        idx.scan([sid], process=False)
        crashed = jobs.claim(idx.store, (jobs.CONVERT,), clock())
        fresh = jobs.claim(idx.store, (jobs.CONVERT,), clock())
        # The process of `crashed` stopped more than STALE_S ago.
        old = clock() - jobs.STALE_S - 1
        idx.store.x("UPDATE job SET updated_at = ? WHERE id = ?", (old, crashed.id))
    assert crashed is not None and fresh is not None
    indexer = Indexer(open_session, nightly_hour=24, watch=False, clock=clock)
    indexer.cycle(jobs=0)
    with open_session() as (_, idx):
        state = dict(idx.store.q("SELECT id, state FROM job WHERE stage = ?", (jobs.CONVERT,)))
    assert state == {crashed.id: jobs.QUEUED, fresh.id: jobs.RUNNING}


def test_nightly_full_scan(setup):
    client, open_session, sid, root, clock = setup
    indexer = Indexer(open_session, nightly_hour=0, watch=False, clock=clock)
    assert indexer.step() == "full"
    assert indexer.state.last_full_scan_day is not None
    assert indexer.step() is None  # once a day
    assert _status(open_session)["last_full_scan_at"] is not None


def test_errors_are_logged_and_kept_in_status(setup, caplog):
    client, open_session, sid, root, clock = setup
    with open_session() as (_, idx):
        idx.add_source(ZoteroFileConnector(root / "gone.json"))
    indexer = Indexer(open_session, nightly_hour=24, watch=False, clock=clock)
    with caplog.at_level(logging.ERROR, logger="anagram.local.index"):
        indexer.step()
    st = _status(open_session)
    assert any("FileNotFoundError" in e["message"] for e in st["errors"])
    assert "FileNotFoundError" in caplog.text
    bad = next(s for s in st["sources"] if s["total"] == 0)
    assert bad["errors"] and "FileNotFoundError" in bad["errors"][0]

    def broken():
        raise RuntimeError("store is gone")

    indexer.open_session = broken
    stop = threading.Event()
    t = threading.Thread(target=indexer.run, args=(stop, 0.01))
    clock.t += 10_000
    t.start()
    time.sleep(0.1)
    stop.set()
    t.join(5)
    assert any("store is gone" in e["message"] for e in indexer.state.errors)


def test_waits_until_ready(setup):
    client, open_session, sid, root, clock = setup
    indexer = Indexer(open_session, ready=lambda: False, watch=False, clock=clock)
    assert indexer.step() is None
    assert _status(open_session) is None


def test_file_events_mark_the_source(setup):
    client, open_session, sid, root, clock = setup
    indexer = Indexer(open_session, nightly_hour=24, watch=True)
    try:
        assert indexer.step() == "poll"
        assert indexer._watched == {sid: [root.resolve()]}
        time.sleep(0.5)
        with indexer._dirty_lock:
            indexer._dirty.clear()
        (root / "new.md").write_text("# New\n")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and sid not in indexer._dirty:
            time.sleep(0.05)
        assert sid in indexer._dirty
    finally:
        indexer._stop_observer()


def test_indexer_error_logs_omit_raw_exception_details(setup, caplog):
    _, open_session, sid, _, clock = setup
    canary = "CANARY-PATH-OR-ITEM-TEXT"

    indexer = Indexer(open_session, nightly_hour=24, watch=False, clock=clock)
    with caplog.at_level(logging.ERROR, logger="anagram.local.index"):
        indexer._error("loop", RuntimeError(f"boom with {canary}"))
    assert canary not in caplog.text
    assert all(not r.exc_info for r in caplog.records)
