"""Tables of the understanding track (integration 1.15, migration I-2).

`CREATE TABLE IF NOT EXISTS` only: `SCHEMA_VERSION` stays 2. `ensure(store)`
applies the tables one time for each open store. Each understanding module calls
it
before it reads or writes these tables.
"""

from __future__ import annotations

import weakref

from anagram.local.index.store import IndexStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS understand_cache (
    key TEXT PRIMARY KEY,
    pass TEXT NOT NULL,
    output TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kind_override (
    item_id INTEGER PRIMARY KEY REFERENCES item(id),
    kind TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS proposal (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ask_log (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    scope TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    citations TEXT NOT NULL,
    mode TEXT NOT NULL,
    model TEXT
);
CREATE TABLE IF NOT EXISTS digest_cache (
    key TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    output TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""
TABLES = ("understand_cache", "kind_override", "proposal", "ask_log", "digest_cache")

# The open stores that have the tables (a store leaves the set when it is freed).
_READY: weakref.WeakSet[IndexStore] = weakref.WeakSet()


def ensure(store: IndexStore) -> None:
    if store in _READY:
        return
    # One statement at a time: `executescript` would end an open transaction.
    for statement in SCHEMA.split(";"):
        if statement.strip():
            store.x(statement)
    _READY.add(store)
