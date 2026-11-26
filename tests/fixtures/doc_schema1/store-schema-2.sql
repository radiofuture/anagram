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
-- Chunks of class `context` (integration 1.9, migration I-3): text that
-- other people wrote (`Document.quoted`, received mail). A table of its own,
-- so no reader of `chunk` (embedding, briefs, proposals, lab items) can get
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
