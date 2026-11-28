"""Encrypted local index store, version 2 (spec/index.md section 5).

One SQLCipher file (`<home>/index.sqlite`) holds all index data: sources,
items, versions with their evidence openings (the salts), checkpoints,
documents, chunks with full-text (FTS5) and vector (sqlite-vec) search, facts,
relations, finding references, the job queue, the status of the background
helper, and the state of each source (accounts with no tokens, cursors, and
the source event log; `source_state.py`).

SQLCipher encrypts each database page with AES-256 and checks it with
HMAC-SHA512 (SQLCipher 4 defaults). The page key is

    db_key = HMAC-SHA256(index_key, "anagram.index.sqlcipher.v1")

given as a raw key (no passphrase derivation: the index key is already 32
random bytes). The index key is `index-key` in the client keystore. The file
shows no plaintext: no path, name, title, chip, text, or table name. Only the
file size and the time of change are visible. A wrong key or a changed page
fails.

The rollback journal (`index.sqlite-journal`) is encrypted in the same way.
The store does not use WAL, so a closed store is exactly one file, and a
backup can copy it as opaque bytes.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import Any

import sqlcipher3

log = logging.getLogger("anagram.local.index")

SCHEMA_VERSION = 2
KEY_LEN = 32
DB_KEY_INFO = b"anagram.index.sqlcipher.v1"
BUSY_TIMEOUT_MS = 30_000
# Page cache limit of one connection.
# SQLCipher keeps decrypted pages only in this cache. With the SQLite
# default (8 MB), each vector search decrypts and checks all vector pages
# again: 10k chunks x 384 float, one search, 54 ms; with a cache that holds
# them, 6 ms. 512 MB holds the vector pages of about 300k chunks (384 float,
# 1.5 kB each) and the hot FTS5 pages. RAM cost: only pages that are read
# stay, up to this limit, while the store is open; a box of 100k chunks
# uses about 160 to 250 MB. Each open connection (the app and the indexer
# helper) has its own cache.
CACHE_MB = 512

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS source (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    config TEXT NOT NULL,
    created_at TEXT NOT NULL,
    seq INTEGER NOT NULL DEFAULT 0,
    prev TEXT,
    start INTEGER NOT NULL DEFAULT 0,
    last_checkpoint_at TEXT,
    prefs TEXT NOT NULL DEFAULT '{}',
    last_scan_at TEXT,
    last_change_at TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS item (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES source(id),
    key TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT,
    media_type TEXT NOT NULL,
    ref TEXT NOT NULL,
    path TEXT,
    mtime_ns TEXT,
    time TEXT,
    digest TEXT NOT NULL,
    present INTEGER NOT NULL,
    seen_at TEXT,
    removed_at TEXT,
    UNIQUE (source_id, key)
);
CREATE TABLE IF NOT EXISTS version (
    id INTEGER PRIMARY KEY,
    item_id INTEGER NOT NULL REFERENCES item(id),
    source_id TEXT NOT NULL,
    n INTEGER NOT NULL,
    digest TEXT NOT NULL,
    digest_hex TEXT NOT NULL,
    media_type TEXT NOT NULL,
    root TEXT NOT NULL UNIQUE,
    opening TEXT NOT NULL,
    checkpoint_seq INTEGER,
    blob BLOB,
    extra TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (item_id, n)
);
CREATE INDEX IF NOT EXISTS version_digest ON version (digest_hex);
CREATE INDEX IF NOT EXISTS version_pending ON version (source_id, checkpoint_seq);
CREATE TABLE IF NOT EXISTS checkpoint (
    source_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    root TEXT NOT NULL,
    opening TEXT NOT NULL,
    item_roots TEXT NOT NULL,
    bundle TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (source_id, seq)
);
CREATE TABLE IF NOT EXISTS document (
    version_id INTEGER PRIMARY KEY REFERENCES version(id),
    converter TEXT NOT NULL,
    converter_version TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT,
    markdown TEXT NOT NULL,
    blocks TEXT NOT NULL,
    meta TEXT NOT NULL,
    quoted TEXT NOT NULL,
    prose INTEGER NOT NULL,
    note TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chunk (
    id INTEGER PRIMARY KEY,
    version_id INTEGER NOT NULL REFERENCES version(id),
    n INTEGER NOT NULL,
    anchor TEXT NOT NULL,
    text TEXT NOT NULL,
    embedded INTEGER NOT NULL DEFAULT 0,
    UNIQUE (version_id, n)
);
CREATE VIRTUAL TABLE IF NOT EXISTS chunk_fts USING fts5(
    text, content='chunk', content_rowid='id', tokenize='porter unicode61'
);
CREATE TRIGGER IF NOT EXISTS chunk_ai AFTER INSERT ON chunk BEGIN
    INSERT INTO chunk_fts (rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS chunk_ad AFTER DELETE ON chunk BEGIN
    INSERT INTO chunk_fts (chunk_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TABLE IF NOT EXISTS fact (
    id INTEGER PRIMARY KEY,
    version_id INTEGER NOT NULL REFERENCES version(id),
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    score REAL NOT NULL DEFAULT 0,
    data TEXT NOT NULL DEFAULT '{}',
    enricher TEXT NOT NULL,
    enricher_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS fact_version ON fact (version_id);
CREATE TABLE IF NOT EXISTS relation (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE (kind, src, dst)
);
CREATE TABLE IF NOT EXISTS finding_ref (
    finding_root TEXT NOT NULL,
    version_id INTEGER NOT NULL REFERENCES version(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (finding_root, version_id)
);
CREATE TABLE IF NOT EXISTS job (
    id INTEGER PRIMARY KEY,
    stage TEXT NOT NULL,
    version_id INTEGER NOT NULL REFERENCES version(id),
    source_id TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at REAL NOT NULL,
    error TEXT,
    reason TEXT,
    fix TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE (stage, version_id)
);
CREATE INDEX IF NOT EXISTS job_ready ON job (state, next_at);
CREATE TABLE IF NOT EXISTS disclosure (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    recipient TEXT NOT NULL,
    adapter TEXT NOT NULL,
    what TEXT NOT NULL,
    source_id TEXT,
    version_id INTEGER
);
CREATE TABLE IF NOT EXISTS status (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS account (
    id TEXT PRIMARY KEY,             -- 16 random bytes, hex
    provider TEXT NOT NULL,          -- google | notion | zotero
    external_id TEXT NOT NULL,       -- the ID of the person at the provider
    label TEXT NOT NULL,             -- email address or workspace name
    client_id TEXT NOT NULL,         -- the OAuth client of the grant ('' for an API key)
    scopes TEXT NOT NULL,            -- JSON list of the granted scopes
    status TEXT NOT NULL,            -- ok | expired | revoked
    created_at TEXT NOT NULL,
    UNIQUE (provider, client_id, external_id)
);
CREATE TABLE IF NOT EXISTS source_state (
    source_id TEXT PRIMARY KEY REFERENCES source(id),
    account_id TEXT,                 -- NULL for a source with no account
    space TEXT NOT NULL DEFAULT 'private',   -- 'private' | 'lab:<lab id>'
    status TEXT NOT NULL DEFAULT 'first_sync',
    paused INTEGER NOT NULL DEFAULT 0,
    cursor TEXT NOT NULL DEFAULT '{}',
    phase TEXT,                      -- first_sync | live | reconcile
    total INTEGER,
    done INTEGER,
    at TEXT,
    skipped INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    error_detail TEXT,
    error_at TEXT,
    failures INTEGER NOT NULL DEFAULT 0,
    next_at REAL NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS source_state_space ON source_state (space);
-- Chunks of class `context`: text that
-- other people wrote (`Document.quoted`, received mail). A table of its own,
-- so no reader of `chunk` (embedding, lens, proposals, lab items) can get
-- it. Only `retrieve.search` reads it, for the private space.
CREATE TABLE IF NOT EXISTS context_chunk (
    id INTEGER PRIMARY KEY,
    version_id INTEGER NOT NULL REFERENCES version(id),
    n INTEGER NOT NULL,
    anchor TEXT NOT NULL,
    text TEXT NOT NULL,
    UNIQUE (version_id, n)
);
CREATE VIRTUAL TABLE IF NOT EXISTS context_fts USING fts5(
    text, content='context_chunk', content_rowid='id', tokenize='porter unicode61'
);
CREATE TRIGGER IF NOT EXISTS context_ai AFTER INSERT ON context_chunk BEGIN
    INSERT INTO context_fts (rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS context_ad AFTER DELETE ON context_chunk BEGIN
    INSERT INTO context_fts (context_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TABLE IF NOT EXISTS source_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    topic TEXT NOT NULL,
    data TEXT NOT NULL               -- JSON, no secrets, no item text
);
"""

# Columns added after schema version 2. `IndexStore` adds a
# missing column when it opens a store, so `SCHEMA_VERSION` stays 2 and an
# old store needs no copy. Old rows get the default.
ADDED_COLUMNS = (
    # The `Document` schema of the row (1: before spans; 2: spans, anchors by content).
    ("document", "schema", "INTEGER NOT NULL DEFAULT 1"),
    # The span of a fact (JSON: anchor, parent, and the fields of `Span`), or NULL.
    ("fact", "span", "TEXT"),
    # `converter@version` of the document that the fact came from, or NULL.
    ("fact", "extractor", "TEXT"),
)


def placeholders(n: int) -> str:
    """`?,?,?` for an SQL `IN (...)` with n values."""
    return ",".join("?" for _ in range(n))


class IndexStoreError(Exception):
    pass


def db_key(index_key: bytes) -> bytes:
    return hmac.new(index_key, DB_KEY_INFO, hashlib.sha256).digest()


def dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def loads(text: str | None) -> Any:
    return None if text is None else json.loads(text)


def _vec_module():
    try:
        import sqlite_vec
    except ImportError:
        return None
    return sqlite_vec


class IndexStore:
    """A thin layer over one SQLCipher connection. `LocalIndex` holds the
    logic. Rows come back as `sqlcipher3.Row` (access by column name)."""

    def __init__(self, path: str | Path, key: bytes) -> None:
        if len(key) != KEY_LEN:
            raise IndexStoreError("index key must be 32 bytes")
        self.path = Path(path)
        if str(path) != ":memory:" and not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
        self._db = sqlcipher3.connect(
            str(self.path), isolation_level=None, timeout=BUSY_TIMEOUT_MS / 1000
        )
        self._db.row_factory = sqlcipher3.Row
        self._depth = 0
        self._db.execute(f"PRAGMA key = \"x'{db_key(key).hex()}'\"")
        try:
            self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except sqlcipher3.DatabaseError as exc:
            self._db.close()
            raise IndexStoreError("index store does not open (wrong key or changed)") from exc
        if str(path) != ":memory:":
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)
        self._db.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        self._db.execute("PRAGMA journal_mode = DELETE")
        # SQLCipher does not encrypt SQLite temp files (sorts, temp tables,
        # VACUUM): with temp_store = FILE they hold plaintext. The sqlcipher3
        # build keeps them in RAM by default (SQLITE_TEMP_STORE=2); this
        # pragma keeps them in RAM with any build.
        self._db.execute("PRAGMA temp_store = MEMORY")
        self._db.execute(f"PRAGMA cache_size = -{CACHE_MB * 1024}")  # in KiB
        self._db.execute("PRAGMA foreign_keys = ON")
        self.vec = self._load_vec()
        self._db.executescript(SCHEMA)
        with self.transaction():
            self._add_columns()
            got = self.get_meta("schema")
            if got is None:
                self.set_meta("schema", SCHEMA_VERSION)
            elif got != SCHEMA_VERSION:
                raise IndexStoreError(f"index store schema {got} is not {SCHEMA_VERSION}")

    def _add_columns(self) -> None:
        for table, col, decl in ADDED_COLUMNS:
            have = {r[1] for r in self._db.execute(f"PRAGMA table_info({table})")}
            if col not in have:
                self._db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    def _load_vec(self) -> bool:
        mod = _vec_module()
        if mod is None:
            log.warning("sqlite-vec is not installed: no vector search")
            return False
        try:
            self._db.enable_load_extension(True)
            self._db.load_extension(mod.loadable_path())
        except Exception:  # the index works without vectors
            log.exception("sqlite-vec does not load: no vector search")
            return False
        finally:
            with contextlib.suppress(Exception):
                self._db.enable_load_extension(False)
        return True

    def close(self) -> None:
        self._db.close()

    # ---------------------------------------------------------------- SQL

    def x(self, sql: str, args: Sequence[Any] = ()) -> sqlcipher3.Cursor:
        return self._db.execute(sql, args)

    def many(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        self._db.executemany(sql, rows)

    def q(self, sql: str, args: Sequence[Any] = ()) -> list:
        return self._db.execute(sql, args).fetchall()

    def one(self, sql: str, args: Sequence[Any] = ()):
        return self._db.execute(sql, args).fetchone()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """`BEGIN IMMEDIATE` ... `COMMIT` (or `ROLLBACK` on an error). A nested
        transaction uses a SQLite `SAVEPOINT` so inner errors roll back cleanly."""
        if self._depth == 0:
            self._db.execute("BEGIN IMMEDIATE")
            self._depth = 1
            ok = False
            try:
                yield
                ok = True
            finally:
                self._depth = 0
                self._db.execute("COMMIT" if ok else "ROLLBACK")
        else:
            self._depth += 1
            sp = f"sp_{self._depth}"
            self._db.execute(f"SAVEPOINT {sp}")
            ok = False
            try:
                yield
                ok = True
            finally:
                self._depth -= 1
                if ok:
                    self._db.execute(f"RELEASE SAVEPOINT {sp}")
                else:
                    self._db.execute(f"ROLLBACK TO SAVEPOINT {sp}")
                    self._db.execute(f"RELEASE SAVEPOINT {sp}")

    # --------------------------------------------------------------- meta

    def get_meta(self, key: str) -> Any:
        row = self.one("SELECT value FROM meta WHERE key = ?", (key,))
        return None if row is None else loads(row[0])

    def set_meta(self, key: str, value: Any) -> None:
        self.x("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, dumps(value)))

    # ------------------------------------------------------------- vectors

    def ensure_vec(self, ident: str, dim: int) -> bool:
        """Make `chunk_vec` for this embedder. A different embedder drops the
        old vectors (they do not mix). Return False without sqlite-vec."""
        if not self.vec:
            return False
        if self.get_meta("embedder") == ident and self._has_table("chunk_vec"):
            return True
        with self.transaction():
            self.x("DROP TABLE IF EXISTS chunk_vec")
            self.x(
                f"CREATE VIRTUAL TABLE chunk_vec USING vec0("
                f"embedding float[{int(dim)}] distance_metric=cosine)"
            )
            self.x("UPDATE chunk SET embedded = 0")
            self.set_meta("embedder", ident)
        return True

    def _has_table(self, name: str) -> bool:
        return self.one("SELECT 1 FROM sqlite_master WHERE name = ?", (name,)) is not None

    def has_vec(self) -> bool:
        return self.vec and self._has_table("chunk_vec")
