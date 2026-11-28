"""The identity database of the node (`identity.sqlite`, layer L1): the
tables, the column changes for an old database, and a one-row query helper.

The admission tables (L4) are in this file too; `AdmissionService` makes them.
"""

from __future__ import annotations

from pathlib import Path

from anagram.core.shared_db import SharedDB

SCHEMA = """
CREATE TABLE IF NOT EXISTS members (
    subject TEXT PRIMARY KEY, role TEXT NOT NULL, joined_at INTEGER NOT NULL, invite TEXT);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, method TEXT NOT NULL,
    expires_at INTEGER NOT NULL, device TEXT);
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY, device_key TEXT NOT NULL, nonce TEXT NOT NULL,
    code_challenge TEXT NOT NULL, return_to TEXT NOT NULL, expires_at INTEGER NOT NULL,
    subject TEXT, name TEXT, code_hash TEXT, attempts INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0, purpose TEXT NOT NULL DEFAULT 'join',
    orcid TEXT, pid TEXT, orcid_salt TEXT, callback_attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY, purpose TEXT NOT NULL, destination TEXT NOT NULL,
    secret_hash TEXT NOT NULL, data TEXT NOT NULL, created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS email_accounts (email TEXT PRIMARY KEY, subject TEXT NOT NULL);
-- Private: never served to the public. `salt` opens `commitment`.
CREATE TABLE IF NOT EXISTS orcid_accounts (
    orcid TEXT PRIMARY KEY, subject TEXT NOT NULL UNIQUE, salt TEXT NOT NULL,
    commitment TEXT NOT NULL, findable INTEGER NOT NULL DEFAULT 0);
-- R8: a person who joined with an invite. `email` is the address that the
-- person stated; it is not proved and is never a sign-in address.
CREATE TABLE IF NOT EXISTS invite_accounts (
    subject TEXT PRIMARY KEY, email TEXT, findable INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL, invite TEXT, device_key TEXT, pending_email TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS invite_accounts_email ON invite_accounts (email);
CREATE TABLE IF NOT EXISTS resolve_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, viewer TEXT NOT NULL, orcid TEXT NOT NULL,
    at INTEGER NOT NULL, answered INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS passkeys (
    credential_id TEXT PRIMARY KEY, subject TEXT NOT NULL, public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS identities (subject TEXT PRIMARY KEY, record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS backups (
    backup_id TEXT PRIMARY KEY, subject TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS directory (
    leaf_index INTEGER PRIMARY KEY, subject TEXT NOT NULL, seq INTEGER NOT NULL,
    entry TEXT NOT NULL);
"""

# The tables that map a sign-in address or iD to a person ID.
ACCOUNT_TABLES = ("orcid_accounts", "email_accounts", "invite_accounts")

# (table, column, SQL type) that a database from before a change does not have.
_ADDED_COLUMNS = (
    ("sessions", "device", "TEXT"),  # security review 2
    ("email_accounts", "findable", "INTEGER NOT NULL DEFAULT 0"),  # find by email
    ("flows", "purpose", "TEXT NOT NULL DEFAULT 'join'"),  # the login purpose
    ("flows", "orcid", "TEXT"),  # person IDs
    ("flows", "pid", "TEXT"),
    ("flows", "orcid_salt", "TEXT"),
    ("flows", "link_subject", "TEXT"),  # the ORCID link
    ("flows", "callback_attempts", "INTEGER NOT NULL DEFAULT 0"),
    ("orcid_accounts", "linked", "INTEGER NOT NULL DEFAULT 0"),  # linked after the join
    ("invite_accounts", "device_key", "TEXT"),
    ("invite_accounts", "pending_email", "TEXT"),
)


def open_db(path: str | Path) -> SharedDB:
    """Open `identity.sqlite`, make the tables, and add the new columns to an
    old database."""
    db = SharedDB(path)
    db.executescript(SCHEMA)
    for table, col, kind in _ADDED_COLUMNS:
        cols = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        if col not in cols:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
    return db


def one(db: SharedDB, sql: str, *args):
    """The first row of a query, or None."""
    return db.execute(sql, args).fetchone()
