"""Encrypted local SQLite files (SQLCipher) of the client.

One function opens a store with a raw key. The raw key is
`HMAC-SHA256(key, info)`, so one keystore key can never open two kinds of
store. This is the scheme of the index store (`anagram.local.index.store`).

`encrypt_in_place` changes a plain SQLite file into an encrypted file with the
same content. It is safe after a stop of the process at each point: the path
always holds a complete file, plain or encrypted.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
from pathlib import Path

import sqlcipher3

from anagram.identity.api import erase_file

KEY_LEN = 32
BUSY_TIMEOUT_MS = 30_000
PLAIN_MAGIC = b"SQLite format 3\x00"
OLD_SUFFIX = ".plain-old"
TMP_MARK = ".enc-tmp"


class LocalDBError(Exception):
    """An encrypted store does not open (wrong key or changed file), or a
    plain store cannot be encrypted."""


def db_key(key: bytes, info: bytes) -> bytes:
    return hmac.new(key, info, hashlib.sha256).digest()


def _pragma_key(raw: bytes) -> str:
    return f"\"x'{raw.hex()}'\""  # hex digits only: safe in the SQL text


def connect(
    path: str | Path, key: bytes, info: bytes, *, timeout_ms: int = BUSY_TIMEOUT_MS
) -> sqlcipher3.Connection:
    """Open (or make) an encrypted store. Raise `LocalDBError` if the file
    does not open with this key."""
    if len(key) != KEY_LEN:
        raise LocalDBError("a store key must be 32 bytes")
    db = sqlcipher3.connect(str(path), isolation_level=None, timeout=timeout_ms / 1000)
    try:
        db.execute(f"PRAGMA key = {_pragma_key(db_key(key, info))}")
        db.execute("SELECT count(*) FROM sqlite_master").fetchone()
        db.execute(f"PRAGMA busy_timeout = {int(timeout_ms)}")
        db.execute("PRAGMA journal_mode = DELETE")
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
    except sqlcipher3.DatabaseError as exc:
        db.close()
        raise LocalDBError(f"{Path(path).name} does not open (wrong key or changed file)") from exc
    return db


def is_plain_sqlite(path: str | Path) -> bool:
    """True if the file is a plain (not encrypted) SQLite database."""
    try:
        with open(path, "rb") as f:
            return f.read(len(PLAIN_MAGIC)) == PLAIN_MAGIC
    except FileNotFoundError:
        return False


def erase_plain_leftovers(path: str | Path) -> None:
    """Erase the old plain copy and any plain SQLite side files that an
    `encrypt_in_place` that stopped left next to the store. Call it only after
    the store at `path` opened with its key."""
    path = Path(path)
    if not is_plain_sqlite(path):
        erase_file(path.with_name(path.name + OLD_SUFFIX))
        for extra in ("-journal", "-wal", "-shm"):
            erase_file(path.with_name(path.name + extra))


def _counts(db: sqlcipher3.Connection, schema: str) -> dict[str, int]:
    tables = [
        r[0]
        for r in db.execute(
            f"SELECT name FROM {schema}.sqlite_master WHERE type = 'table'"  # noqa: S608
        )
    ]
    out = {}
    for t in sorted(tables):
        quoted = '"' + t.replace('"', '""') + '"'
        out[t] = db.execute(f"SELECT count(*) FROM {schema}.{quoted}").fetchone()[0]  # noqa: S608
    return out


def encrypt_in_place(path: str | Path, key: bytes, info: bytes) -> None:
    """Change the plain SQLite file at `path` into an encrypted store.

    1. Export all content to a new encrypted temp file and compare the row
       count of each table.
    2. Give the plain file a second name (`<path>.plain-old`), then rename the
       encrypted file onto `path` (atomic).
    3. Write zeros on the plain file and remove it.

    The caller must make sure that no other process writes to the store during
    this call."""
    path = Path(path)
    if len(key) != KEY_LEN:
        raise LocalDBError("a store key must be 32 bytes")
    if not is_plain_sqlite(path):
        raise LocalDBError(f"{path.name} is not a plain SQLite file")
    for stale in path.parent.glob(f"{path.name}{TMP_MARK}*"):
        erase_file(stale)
    tmp = path.with_name(f"{path.name}{TMP_MARK}-{secrets.token_hex(4)}")
    old = path.with_name(path.name + OLD_SUFFIX)
    try:
        db = sqlcipher3.connect(str(path), isolation_level=None)
        try:
            db.execute(
                f"ATTACH DATABASE ? AS enc KEY {_pragma_key(db_key(key, info))}", (str(tmp),)
            )
            db.execute("SELECT sqlcipher_export('enc')")
            version = db.execute("PRAGMA main.user_version").fetchone()[0]
            db.execute(f"PRAGMA enc.user_version = {int(version)}")
            same = _counts(db, "main") == _counts(db, "enc")
            db.execute("DETACH DATABASE enc")
        finally:
            db.close()
        if not same:
            raise LocalDBError(f"the encrypted copy of {path.name} does not agree")
        os.chmod(tmp, 0o600)
        check = connect(tmp, key, info)  # the new file opens with the key
        check.close()
        fd = os.open(tmp, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        # A try that stopped between the link and the rename left `old` as a
        # second name of the plain file: remove the name, not the bytes.
        if old.exists() and os.path.samefile(old, path):
            os.unlink(old)
        else:
            erase_file(old)
        os.link(path, old)
        os.replace(tmp, path)
    except sqlcipher3.DatabaseError as exc:
        raise LocalDBError(f"{path.name} cannot be encrypted") from exc
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
    erase_file(old)
    for extra in ("-journal", "-wal", "-shm"):  # plain side files of the old store
        erase_file(path.with_name(path.name + extra))
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
