"""Durable file writes.

`atomic_write` gives a file that is the old bytes or the new bytes after a
crash or a power loss, never a part of them, and that no other user can
read at any time: the temporary file is made with its mode (no chmod after
the write), the data and then the directory are synced to disk, and only
then does the new name replace the old one.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path


def fsync_dir(directory: str | Path) -> None:
    """Sync a directory, so that a new or replaced name in it is on disk."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: str | Path, data: bytes, mode: int = 0o600) -> None:
    """Write `data` to `path` atomically and durably, with `mode`."""
    target = Path(path)
    tmp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    fsync_dir(target.parent)
