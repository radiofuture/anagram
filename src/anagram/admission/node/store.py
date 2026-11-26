"""The node tables of admission (layer L4). They are in `identity.sqlite`,
on the connection of the identity service, so that a claim and the new
member row are one action under one lock. The data did not move
when this code moved to the admission layer.

`AdmissionStore` is the one object through which admission code reads and
writes these tables. The composition root (`NodeHome`) makes it from the
connection and the store lock of the identity service.

Lock contract (docs/design/shared-sqlite-connection.md):

- `db` is the `SharedDB` connection of the identity store. Each call holds
  the connection lock, and `execute` reads all rows before it releases it.
- `lock` is the store lock of the identity service. Take it first for work
  with more than one statement (for example a claim and the new member row).
  The connection lock never takes a store lock, so the order cannot deadlock.
"""

from __future__ import annotations

import threading

from anagram.core.shared_db import SharedDB

# The node invite rows. `role`: member, organizer, or reader. A row keeps the
# hash of the token only (`id`), never the token.
INVITES_SCHEMA = """
CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY, created_by TEXT, created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL, claimed_by TEXT, receipt TEXT);
"""

# The reader invites (a finding shared with a person who is not a member yet).
READER_SCHEMA = """
CREATE TABLE IF NOT EXISTS reader_invites (
    invite_id TEXT PRIMARY KEY, owner TEXT NOT NULL, contact_kind TEXT NOT NULL,
    contact TEXT NOT NULL, state TEXT NOT NULL, subject TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, mailed_at INTEGER);
CREATE INDEX IF NOT EXISTS reader_invites_by_owner ON reader_invites (owner, state);
CREATE INDEX IF NOT EXISTS reader_invites_by_subject ON reader_invites (subject);
"""


def ensure_tables(db) -> None:
    db.executescript(INVITES_SCHEMA)
    cols = {r[1] for r in db.execute("PRAGMA table_info(invites)")}
    if "role" not in cols:  # a database from before organizer invites
        db.execute("ALTER TABLE invites ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
    db.executescript(READER_SCHEMA)


class AdmissionStore:
    """The admission tables on the identity connection (see the lock
    contract in the module text)."""

    def __init__(self, db: SharedDB, lock: threading.RLock) -> None:
        self.db = db
        self.lock = lock
        ensure_tables(db)
