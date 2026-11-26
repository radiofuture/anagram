"""Node SQLite stores under many threads (`anagram.core.shared_db`).

The HTTP server calls each store from many threads, and every store keeps one
connection. Before `SharedDB`, some methods used that connection without the
store lock, which gave "database is locked" and a crash of the sqlite3 module
under load. The stress run is in a child process, so that a crash is a test
failure and does not stop the suite.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from anagram.core.shared_db import SharedDB

THREADS = 12
ROUNDS = 150


def test_shared_db_settings(tmp_path):
    db = SharedDB(tmp_path / "x.sqlite")
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert db.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000
    db.execute("CREATE TABLE t (k INTEGER PRIMARY KEY, v TEXT)")
    cur = db.execute("INSERT INTO t (v) VALUES ('a')")
    assert (cur.lastrowid, cur.rowcount) == (1, 1)
    db.executemany("INSERT INTO t (v) VALUES (?)", [("b",), ("c",)])
    rows = db.execute("SELECT v FROM t ORDER BY k")
    assert rows.fetchone() == ("a",)
    assert list(rows) == [("b",), ("c",)]
    assert rows.fetchone() is None and rows.fetchall() == []
    db.close()


def _hammer(name: str, call, errors: list) -> None:
    for i in range(ROUNDS):
        try:
            call(i)
        except Exception as exc:  # the parent reports all of them
            errors.append(f"{name}: {exc!r}")
            return


def _raw(db):
    """Writes and reads through the store's own connection, as its methods do."""
    db.execute("CREATE TABLE IF NOT EXISTS stress (k TEXT PRIMARY KEY, v TEXT)")

    def call(i: int) -> None:
        key = f"{threading.get_ident()}-{i % 8}"
        db.execute("INSERT OR REPLACE INTO stress VALUES (?, ?)", (key, "x" * 64))
        n = sum(1 for _ in db.execute("SELECT k FROM stress WHERE k LIKE ?", (key[:-1] + "%",)))
        row = db.execute("SELECT v FROM stress WHERE k = ?", (key,)).fetchone()
        assert n > 0 and row is not None, "a row is lost"

    return call


def stress(root: Path) -> list[str]:
    sys.path.insert(0, str(Path(__file__).parent))
    from conftest import make_net

    from anagram.core.errors import NotFound
    from anagram.proofs.log.store import SQLiteLog
    from anagram.proofs.node.anchoring import AnchorScheduler

    net = make_net(root)
    nh, identity = net.home, net.identity
    stores = {
        "identity": identity,
        "vault": net.vault,
        "store": net.store,
        "labs": net.labs,
        "admin": nh.admin(identity, nh.admission(identity)),
        "reads": nh.reads(identity, net.vault),
        "verify": nh.verify(identity),
        "reader_invites": nh.reader_invites(identity),
        "anchoring": AnchorScheduler(
            net.service.store, net.service.origin, {}, nh.dir / "anchors.sqlite"
        ),
        "log": SQLiteLog(root / "log.sqlite"),
    }
    log = stores["log"]
    log.append(b"first")

    def log_calls(i: int) -> None:  # the anchor thread appends, HTTP threads read
        log.append(f"entry {i}".encode())
        size = log.size()
        log.entry(size - 1)
        log.root(size)

    def identity_calls(i: int) -> None:  # public methods that had no lock
        net.admission.create_invite(None, 7)
        net.admission.open_invites()
        identity.community_stats()
        net.labs.directory.labs_of("nobody")
        identity.identity_record("nobody")
        stores["admin"].owns("nobody")
        try:
            stores["verify"].published("00" * 32)
        except NotFound:
            pass

    calls = [("identity-public", identity_calls), ("log-public", log_calls)]
    calls += [(name, _raw(s._db)) for name, s in stores.items()]
    errors: list[str] = []
    threads = [
        threading.Thread(target=_hammer, args=(name, call, errors))
        for name, call in calls
        for _ in range(THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_stores_under_many_threads(tmp_path):
    proc = subprocess.run(  # noqa: S603 - this file, with a test directory
        [sys.executable, __file__, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "HF_HUB_OFFLINE": "1"},
    )
    if proc.returncode != 0:
        pytest.fail(f"stress run failed (exit {proc.returncode}):\n{proc.stdout}\n{proc.stderr}")


if __name__ == "__main__":
    errs = stress(Path(sys.argv[1]))
    print("\n".join(errs[:20]))
    sys.exit(1 if errs else 0)
