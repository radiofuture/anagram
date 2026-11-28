"""The spend ledger under parallel threads (the P4 crash of 2026-11-16:
`database is locked` in `BudgetLedger.finish` after 6,900 of 8,158 parallel
judge calls). A reserve or a finish must never fail on lock contention."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

from anagram.models import ledger as ledger_mod
from anagram.models.ledger import LEDGER_WAIT_SECONDS, BudgetLedger

THREADS = 48
CALLS = 25  # for each thread


def _work(ledger: BudgetLedger, n: int) -> int:
    done = 0
    for i in range(n):
        key = ledger.reserve("judge:test", 1000)
        ledger.finish(key, {"cost": "0.0000005", "input_tokens": i, "output_tokens": 1})
        if i % 5 == 0:
            ledger.snapshot()  # a reader at the same time (the run prints it)
        done += 1
    return done


def _run(ledgers: list[BudgetLedger]) -> list[BaseException]:
    errors: list[BaseException] = []
    gate = threading.Barrier(THREADS)

    def one(i: int) -> int:
        gate.wait()
        try:
            return _work(ledgers[i % len(ledgers)], CALLS)
        except BaseException as exc:  # the test collects each error
            errors.append(exc)
            return 0

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        list(ex.map(one, range(THREADS)))
    return errors


def _check(path) -> None:
    with sqlite3.connect(path) as db:
        statuses = dict(db.execute("SELECT status, count(*) FROM calls GROUP BY status"))
    assert statuses == {"reported": THREADS * CALLS}


def test_one_ledger_many_threads(tmp_path):
    """Many threads of one ledger object (the harness: one judge, a pool)."""
    ledger = BudgetLedger(tmp_path / "spend.sqlite", "100")
    errors = _run([ledger])
    assert errors == []
    _check(tmp_path / "spend.sqlite")
    snap = ledger.snapshot()
    assert snap["calls"] == THREADS * CALLS
    assert snap["reported_nanousd"] == THREADS * CALLS * 500
    assert not snap["breached"]


def test_many_ledger_objects_one_file(tmp_path):
    """One ledger object for each thread on one file: no shared Python lock,
    as two processes of one node."""
    path = tmp_path / "spend.sqlite"
    ledgers = [BudgetLedger(path, "100") for _ in range(8)]
    errors = _run(ledgers)
    assert errors == []
    _check(path)


def test_waits_for_a_slow_writer(tmp_path, monkeypatch):
    """Another process holds the write lock longer than sqlite's busy timeout.
    The default timeout is well past the old 5 s sqlite default, and each
    reserve and finish of parallel threads retries cleanly until the writer
    commits; none fails."""
    path = tmp_path / "spend.sqlite"
    ledger = BudgetLedger(path, "100")
    assert LEDGER_WAIT_SECONDS >= 30.0
    db = ledger._connect()
    try:
        assert db.execute("PRAGMA busy_timeout").fetchone()[0] == int(LEDGER_WAIT_SECONDS * 1000)
    finally:
        db.close()

    # Use a short SQLite busy_timeout while keeping the retry deadline generous
    # so the lock contention + Python retry backoff path is exercised fast.
    real_connect = ledger._connect

    def short_busy() -> sqlite3.Connection:
        con = real_connect()
        con.execute("PRAGMA busy_timeout = 50")
        return con

    monkeypatch.setattr(ledger, "_connect", short_busy)
    monkeypatch.setattr(ledger_mod, "LEDGER_WAIT_SECONDS", 10.0)

    holder = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    holder.execute("BEGIN IMMEDIATE")
    release = threading.Timer(0.25, lambda: holder.execute("COMMIT"))
    release.start()
    try:
        errors: list[BaseException] = []

        def one(_: int) -> None:
            try:
                _work(ledger, 3)
            except BaseException as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(one, range(8)))
    finally:
        release.join()
        holder.close()
    assert errors == []
    assert ledger.snapshot()["calls"] == 24


def test_limit_holds_under_contention(tmp_path):
    """The limit stays exact when many threads reserve at the same time."""
    ledger = BudgetLedger(tmp_path / "spend.sqlite", "0.000100")  # 100,000 nano
    got: list[str] = []
    refused = []
    lock = threading.Lock()

    def one(_: int) -> None:
        for _ in range(20):
            try:
                key = ledger.reserve("judge:test", 1000)
            except Exception as exc:
                with lock:
                    refused.append(str(exc))
                continue
            with lock:
                got.append(key)
            ledger.finish(key, {"cost": "0.000001"})

    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(one, range(16)))
    assert len(got) == 100
    assert set(refused) == {"spend_limit_reached"}
    assert ledger.snapshot()["reserved_nanousd"] == 100_000
