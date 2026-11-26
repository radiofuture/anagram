# Shared SQLite connection

A design pattern of Anagram (`anagram.core.shared_db`). Use it when a server
keeps one SQLite connection and calls it from many threads, for example the
request threads of an HTTP server.

Rules:

- Open the connection one time, through the helper. Do not call
  `sqlite3.connect(..., check_same_thread=False)` in a store.
- The helper takes one re-entrant lock for each call (`execute`,
  `executemany`, `executescript`, `close`), so a store method cannot forget
  it.
- `execute` reads all rows before it releases the lock, and returns them
  with `lastrowid` and `rowcount`. No cursor stays open on the connection.
- Set WAL and a busy timeout (30 s), so that a second connection to the same
  file (a CLI command, a test) waits and does not fail with
  "database is locked".
- A store keeps its own lock for work with more than one statement. Take the
  store lock first. The helper lock never takes a store lock, so the lock
  order cannot deadlock.
- Keep transactions short: autocommit, and no network or model call while a
  lock is held.

Tests: a stress run with many threads against each store, in a child
process, so that a crash of the sqlite3 module is a test failure
(`tests/test_shared_db.py`).
