"""The spend ledger and the paid-run checks of paid model calls.

`BudgetLedger` keeps durable spend reservations. `check_paid_runs` checks an
approved budget. The price tables give USD for each million tokens. The model
gate (`budget.Gate`) uses them.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import closing
from datetime import date
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from pathlib import Path


class EngineError(Exception):
    """An engine refused to run (config, budget, or cap)."""


def usd_text(value: Decimal) -> str:
    """A dollar amount as text: at most 4 decimals, no trailing zeros."""
    return format(value.quantize(Decimal("0.0001")).normalize(), "f")


def nanodollars(value: object) -> int:
    """USD to integer nanodollars. Refuse negative, fractional, or huge values."""
    try:
        d = Decimal(str(value)) * 10**9
    except (InvalidOperation, ValueError) as exc:
        raise EngineError("invalid_usd_amount") from exc
    if not d.is_finite() or d < 0 or d != d.to_integral_value() or d > 10**15:
        raise EngineError("invalid_usd_amount")
    return int(d)


# A ledger write waits this long for the lock of another thread or process.
# It is far more than one write takes; only a stuck writer goes over it.
LEDGER_WAIT_SECONDS = 120.0
_LEDGER_LOCKS: dict[str, threading.Lock] = {}
_LEDGER_LOCKS_LOCK = threading.Lock()


def _ledger_lock(path: Path) -> threading.Lock:
    """One lock for each ledger file in this process, shared by each
    `BudgetLedger` object of that file."""
    name = str(path.resolve())
    with _LEDGER_LOCKS_LOCK:
        return _LEDGER_LOCKS.setdefault(name, threading.Lock())


def _busy(exc: sqlite3.OperationalError) -> bool:
    text = str(exc).lower()
    return "locked" in text or "busy" in text


class BudgetLedger:
    """Durable spend reservations in integer nanodollars (USD * 1e9).

    Reserve before each paid call. A reservation is never refunded: failures,
    price changes, and missing usage stay bounded by the limit.

    Safe for parallel threads and processes (the run of 2026-11-16 stopped
    on `database is locked` in `finish`): the file uses WAL mode and a busy
    timeout, each write is one short `BEGIN IMMEDIATE` transaction, the
    threads of one process take one lock for each file, and a write that
    gets a lock error tries again until `LEDGER_WAIT_SECONDS`. After that it
    raises `EngineError("ledger_busy")`, so a paid judge stops cleanly."""

    def __init__(self, path: str | Path, limit_usd: object) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self._lock = _ledger_lock(self.path)
        limit = nanodollars(limit_usd)

        def setup(db: sqlite3.Connection) -> int:
            db.execute(
                "CREATE TABLE IF NOT EXISTS budget (id INTEGER PRIMARY KEY CHECK(id=1),"
                " limit_nano INTEGER NOT NULL, breached INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, route TEXT NOT NULL,"
                " reserved_nano INTEGER NOT NULL, status TEXT NOT NULL,"
                " reported_nano INTEGER, usage TEXT)"
            )
            db.execute("INSERT OR IGNORE INTO budget(id, limit_nano) VALUES(1, ?)", (limit,))
            return db.execute("SELECT limit_nano FROM budget").fetchone()[0]

        with self._lock, closing(self._connect()) as db:
            # WAL: readers do not block the writer, and the writer does not
            # block readers. The mode stays in the file.
            self._retry(lambda: db.execute("PRAGMA journal_mode=WAL").fetchone())
        stored = self._write(setup)
        if stored != limit:
            raise EngineError("budget_limit_mismatch")
        self.limit_nano = limit

    def _connect(self) -> sqlite3.Connection:
        timeout_ms = int(LEDGER_WAIT_SECONDS * 1000)
        db = sqlite3.connect(self.path, timeout=LEDGER_WAIT_SECONDS, isolation_level=None)
        db.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        return db

    def _retry(self, body: Callable[[], object]) -> object:
        """Run `body`; on a lock error, wait a short time and try again."""
        deadline = time.monotonic() + LEDGER_WAIT_SECONDS
        pause = 0.005
        while True:
            try:
                return body()
            except sqlite3.OperationalError as exc:
                if not _busy(exc):
                    raise
                if time.monotonic() > deadline:
                    raise EngineError("ledger_busy") from None
                time.sleep(pause)
                pause = min(pause * 2, 0.25)

    def _write(self, body: Callable[[sqlite3.Connection], object]) -> object:
        """One short write transaction. All or nothing; tried again on a lock
        error. An error of `body` (for example the spend limit) rolls back."""

        def once() -> object:
            with closing(self._connect()) as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    out = body(db)
                    db.execute("COMMIT")
                    return out
                except BaseException:
                    if db.in_transaction:
                        db.execute("ROLLBACK")
                    raise

        with self._lock:
            return self._retry(once)

    def reserve(self, route: str, amount_nano: int) -> str:
        if type(amount_nano) is not int or amount_nano <= 0:
            raise EngineError("invalid_reservation")

        def body(db: sqlite3.Connection) -> str:
            limit, breached = db.execute("SELECT limit_nano, breached FROM budget").fetchone()
            total = db.execute("SELECT coalesce(sum(reserved_nano), 0) FROM calls").fetchone()[0]
            if breached or total + amount_nano > limit:
                raise EngineError("spend_limit_reached")
            key = uuid.uuid4().hex
            db.execute(
                "INSERT INTO calls(id, route, reserved_nano, status) VALUES(?, ?, ?, 'reserved')",
                (key, route, amount_nano),
            )
            return key

        return self._write(body)  # type: ignore[return-value]

    def finish(self, key: str, usage: dict | None = None) -> None:
        usage = usage or {}
        reported: int | None = None
        invalid_cost = False
        if "cost" in usage:
            raw_cost = usage["cost"]
            if isinstance(raw_cost, bool) or raw_cost is None:
                invalid_cost = True
            else:
                try:
                    amount = Decimal(str(raw_cost)) * 10**9
                except (InvalidOperation, ValueError):
                    invalid_cost = True
                else:
                    if amount.is_finite() and 0 <= amount <= 10**15:
                        reported = int(amount.to_integral_value(rounding=ROUND_CEILING))
                    else:
                        invalid_cost = True

        def body(db: sqlite3.Connection) -> str | None:
            reserved = db.execute(
                "SELECT reserved_nano FROM calls WHERE id = ?", (key,)
            ).fetchone()[0]
            if invalid_cost:
                reason: str | None = "invalid_reported_cost"
                status = "cost_invalid"
            elif reported is not None and reported > reserved:
                reason = "provider_exceeded_reservation"
                status = "reported"
            else:
                reason = None
                status = "reported" if reported is not None else "cost_unknown"
            db.execute(
                "UPDATE calls SET status = ?, reported_nano = ?, usage = ? WHERE id = ?",
                (status, reported, json.dumps(usage), key),
            )
            if reason is not None:
                db.execute("UPDATE budget SET breached = 1")
            return reason

        reason = self._write(body)
        if reason is not None:
            raise EngineError(str(reason))

    def halt(self) -> None:
        self._write(lambda db: db.execute("UPDATE budget SET breached = 1"))

    def snapshot(self) -> dict:
        def read() -> tuple:
            with closing(self._connect()) as db:
                # One read transaction, so the two reads agree.
                db.execute("BEGIN")
                try:
                    budget = db.execute("SELECT limit_nano, breached FROM budget").fetchone()
                    calls = db.execute(
                        "SELECT count(*), coalesce(sum(reserved_nano), 0),"
                        " coalesce(sum(reported_nano), 0) FROM calls"
                    ).fetchone()
                finally:
                    db.execute("COMMIT")
                return budget, calls

        (limit, breached), (count, reserved, reported) = self._retry(read)  # type: ignore[misc]
        return {
            "breached": bool(breached),
            "calls": count,
            "limit_nanousd": limit,
            "reported_nanousd": reported,
            "reserved_nanousd": reserved,
        }


# USD per million tokens (input, output), for prompts of 100,000 tokens or
# fewer. Checked 2026-10-27 on platform.claude.com/docs/en/about-claude/pricing
# (Claude Haiku 5.5: $0.10 input, $0.50 output; prompts over 100,000 tokens
# cost more, and a judge prompt is far below that).
ANTHROPIC_PRICES = {
    "claude-opus-5-5": (Decimal("4.00"), Decimal("20.00")),
    "claude-sonnet-5-5": (Decimal("2.00"), Decimal("10.00")),
    "claude-haiku-5-5": (Decimal("0.10"), Decimal("0.50")),
}
# OpenRouter model IDs. Checked 2026-10-27 on openrouter.ai/api/v1/models:
# anthropic/claude-haiku-5.5 has prompt $0.0000001 and completion $0.0000005
# for each token (prompts under 100,000 tokens). Its reasoning is not
# mandatory ("none" is a supported effort).
OPENROUTER_PRICES = {
    "anthropic/claude-haiku-5.5": (Decimal("0.10"), Decimal("0.50")),
}
PRICES = {**ANTHROPIC_PRICES, **OPENROUTER_PRICES}
LONG_PROMPT_TOKENS = 100_000


def check_paid_runs(paid_runs: object, today: date | None = None) -> dict:
    """A paid engine needs `paid_runs: {approved_by, budget_usd, expires}`.
    `expires` is an ISO date. Each approval names the approver."""
    if not isinstance(paid_runs, dict) or set(paid_runs) != {
        "approved_by",
        "budget_usd",
        "expires",
    }:
        raise EngineError("paid engine needs paid_runs: {approved_by, budget_usd, expires}")
    if not isinstance(paid_runs["approved_by"], str) or not paid_runs["approved_by"].strip():
        raise EngineError("paid_runs.approved_by is empty")
    if nanodollars(paid_runs["budget_usd"]) <= 0:
        raise EngineError("paid_runs.budget_usd must be more than 0")
    try:
        expires = date.fromisoformat(str(paid_runs["expires"]))
    except ValueError as exc:
        raise EngineError("paid_runs.expires must be an ISO date") from exc
    if expires < (today or date.today()):
        raise EngineError("paid_runs approval has expired")
    return paid_runs


def estimate_usd(model_id: str, input_tokens: int, output_tokens: int) -> Decimal:
    price_in, price_out = PRICES[model_id]
    return (price_in * input_tokens + price_out * output_tokens) / Decimal(1_000_000)
