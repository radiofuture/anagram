"""`hosting.runtime.Ticker`, the one timer loop of the services and the
node."""

from __future__ import annotations

import logging
import threading

import pytest

from anagram.network.matching.hosting.runtime import Ticker


def test_a_failed_tick_is_logged_and_the_next_tick_runs(caplog: pytest.LogCaptureFixture) -> None:
    calls: list[int] = []
    again = threading.Event()

    def tick() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("the first tick fails")
        again.set()

    caplog.set_level(logging.WARNING, logger="anagram.services.test")
    ticker = Ticker("test", tick, every=0.01).start()
    try:
        assert again.wait(5)
    finally:
        ticker.stop()
    failed = [r for r in caplog.records if r.getMessage() == "tick_failed"]
    assert failed and failed[0].fields == {"event": "tick_failed", "error": "RuntimeError"}  # type: ignore[attr-defined]


def test_stop_ends_the_thread_and_no_tick_runs_after_it() -> None:
    calls: list[int] = []
    ran = threading.Event()

    def tick() -> None:
        calls.append(1)
        ran.set()

    ticker = Ticker("test", tick, every=0.01).start()
    assert ran.wait(5)
    ticker.stop()
    count = len(calls)
    assert not ticker._thread.is_alive()  # noqa: SLF001 - the test checks the thread
    threading.Event().wait(0.05)
    assert len(calls) == count
