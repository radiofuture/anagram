"""A lock file: one process for each data directory.

`acquire(path)` returns a handle, or None if another process (or another
handle in this process) holds the lock. The operating system releases the
lock when the process stops, also after a crash. POSIX: `fcntl.flock`.
Windows: `msvcrt.locking` on the first byte.
"""

from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path


class LockHandle:
    def __init__(self, path: Path, fd: int) -> None:
        self.path = path
        self._fd: int | None = fd

    @property
    def held(self) -> bool:
        return self._fd is not None

    def release(self) -> None:
        """Release the lock. The file stays (a removed file can give two
        holders: one on the old file and one on a new file)."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        with contextlib.suppress(OSError):
            _unlock(fd)
        os.close(fd)

    def __enter__(self) -> LockHandle:
        return self

    def __exit__(self, *exc) -> None:
        self.release()


if sys.platform == "win32":  # pragma: no cover - Windows only
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def acquire(path: str | Path) -> LockHandle | None:
    """Take the lock and return its handle. None: the lock is held."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _lock(fd)
    except OSError:
        os.close(fd)
        return None
    return LockHandle(path, fd)
