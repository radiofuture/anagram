"""One SQLite connection that many server threads can use safely.

The node stores (identity, labs, vault, reads, and others) each keep one
connection and serve it from the threads of the HTTP server. A store lock
does not always cover every statement, and a cursor that is read after the
lock is released still uses the connection. Both can give "database is
locked" or a crash in the sqlite3 module.

`SharedDB` puts the lock into the connection: each call runs under one
re-entrant lock, and `execute` reads all rows before it releases the lock.
The store lock stays for multi-statement work; take it first, then this
lock (this lock never takes a store lock, so the order cannot deadlock).
WAL and a busy timeout let a second connection to the same file (a CLI
command, a test) wait instead of fail. See docs/design/shared-sqlite-connection.md.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

BUSY_TIMEOUT_MS = 30_000


class Rows:
    """The full result of one statement, read while the lock was held."""

    __slots__ = ("_rows", "_pos", "lastrowid", "rowcount", "description")

    def __init__(self, cur: sqlite3.Cursor) -> None:
        self._rows = cur.fetchall()
        self._pos = 0
        self.lastrowid = cur.lastrowid
        self.rowcount = cur.rowcount
        self.description = cur.description

    def fetchone(self) -> Any:
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return row

    def fetchall(self) -> list[Any]:
        rest = self._rows[self._pos :]
        self._pos = len(self._rows)
        return rest

    def __iter__(self) -> Iterator[Any]:
        while (row := self.fetchone()) is not None:
            yield row


# The parameters of one statement: by position or by name (as in sqlite3).
type Params = Sequence[Any] | Mapping[str, Any]


class SharedDB:
    """A sqlite3 connection where every call holds one lock."""

    def __init__(self, path: str | Path, *, wal: bool = True) -> None:
        self.lock = threading.RLock()
        self._con = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            timeout=BUSY_TIMEOUT_MS / 1000,
        )
        with self.lock:
            self._con.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
            if wal and str(path) != ":memory:":
                self._con.execute("PRAGMA journal_mode = WAL")

    def execute(self, sql: str, params: Params = ()) -> Rows:
        with self.lock:
            return Rows(self._con.execute(sql, params))

    def executemany(self, sql: str, seq: Iterable[Params]) -> Rows:
        with self.lock:
            return Rows(self._con.executemany(sql, seq))

    def executescript(self, script: str) -> None:
        with self.lock:
            self._con.executescript(script)

    def close(self) -> None:
        with self.lock:
            self._con.close()
