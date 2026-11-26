"""Find plaintext on disk (plan net 01 step 4; plan net 02 runs it in each
converter test).

A test plants known bytes (canary words, the raw float32 bytes of a known
vector) in the data, runs the code, and then:

- `scan(roots, needles)` reads each file under the roots (also journal,
  temp, and sidecar files) and reports each needle that it finds.
- `temp_roots()` gives the OS temp folders (`TMPDIR`, `tempfile`, `/tmp`,
  `/var/tmp`, `SQLITE_TMPDIR`). Scan them with `since` (only files changed
  after the start of the test), because other programs write there too.
- `FdWatch` sees files that are deleted at once after they open (SQLite
  temp files are such files): it reads the open file descriptors of this
  process, and reads and scans each regular file outside the allowed
  folders while it is open. A test that must prove a result calls
  `FdWatch.poll` at the point where the file is open, or sets
  `FdWatch.progress` as the SQLite progress handler of the connection, so
  that a poll runs inside each statement. Then the result does not depend
  on the scheduler. The background thread is an extra watch for files that
  no hook reaches.

Test tool only (layer XT); no product code imports it.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

BLOCK = 4 << 20
MAX_READ = 256 << 20
CODE = (".py", ".pyc", ".so", ".dylib")  # files of the program, not data


def text_needles(words: Iterable[str]) -> list[bytes]:
    return [w.encode("utf-8") for w in words]


def float32_needles(vectors: Iterable[Sequence[float]], run: int = 8) -> list[bytes]:
    """`run` float32 values (little-endian) from the start and from the
    middle of each vector. Any engine that writes the vector as float32
    writes these bytes. A run with fewer than 4 different nonzero values is
    left out (a run of zeros is in many files)."""
    import struct

    out = []
    for v in vectors:
        vals = [float(x) for x in v]
        mid = len(vals) // 2
        for part in (vals[:run], vals[mid : mid + run]):
            if len(part) == run and len({x for x in part if x}) >= 4:
                out.append(struct.pack(f"<{run}f", *part))
    return out


@dataclass(frozen=True)
class Hit:
    path: str
    needle: int  # index in the needle list


def _find(data: bytes, needles: Sequence[bytes]) -> set[int]:
    return {i for i, n in enumerate(needles) if n and n in data}


def scan_file(path: Path, needles: Sequence[bytes]) -> set[int]:
    over = max((len(n) for n in needles), default=1) - 1
    found: set[int] = set()
    tail = b""
    try:
        with path.open("rb") as f:
            while block := f.read(BLOCK):
                found |= _find(tail + block, needles)
                tail = block[-over:] if over else b""
    except OSError:
        return set()
    return found


def _changed_since(path: Path, since: float) -> bool:
    try:
        st = path.lstat()
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and max(st.st_mtime, st.st_ctime) >= since


def scan(
    roots: Iterable[str | Path],
    needles: Sequence[bytes],
    *,
    since: float | None = None,
    skip: Iterable[str | Path] = (),
) -> list[Hit]:
    """Each needle found in a regular file under `roots` (no symlinks).
    `skip`: folders to leave out (for example the plaintext corpus of the
    test).

    `since`: only files with a change time at or after it, and only folders
    with such a change time below the root (a new file changes the time of
    its folder). The OS temp folder of a desktop holds many old folders; this
    keeps the scan short. SQLite and `tempfile` write at the top of the temp
    folder."""
    skipped = [Path(s).resolve() for s in skip]
    hits: list[Hit] = []
    seen: set[Path] = set()
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            here = Path(dirpath).resolve()
            if any(here == s or s in here.parents for s in skipped):
                dirnames[:] = []
                continue
            if since is not None:
                dirnames[:] = [d for d in dirnames if _changed_since(here / d, since)]
            for name in filenames:
                p = here / name
                if p in seen:
                    continue
                seen.add(p)
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if since is not None and max(st.st_mtime, st.st_ctime) < since:
                    continue
                hits += [Hit(str(p), i) for i in sorted(scan_file(p, needles))]
    return hits


def temp_roots() -> list[Path]:
    """The OS temp folders that exist (resolved, no repeats)."""
    names = [
        os.environ.get("TMPDIR"),
        os.environ.get("SQLITE_TMPDIR"),
        tempfile.gettempdir(),
        "/tmp",  # noqa: S108 (scanned, not written)
        "/var/tmp",  # noqa: S108
    ]
    out: list[Path] = []
    for n in names:
        if n and Path(n).is_dir():
            p = Path(n).resolve()
            if p not in out:
                out.append(p)
    return out


def _fd_path(fd: int) -> str | None:
    if sys.platform == "darwin":
        import fcntl

        try:
            raw = fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024))
        except OSError:
            return None
        return raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None


def _open_fds() -> list[int]:
    folder = "/dev/fd" if sys.platform == "darwin" else "/proc/self/fd"
    try:
        return [int(x) for x in os.listdir(folder)]
    except OSError:
        return []


@dataclass
class OpenFile:
    path: str
    deleted: bool
    size: int
    hits: set[int] = field(default_factory=set)


class FdWatch:
    """Watch the open files of this process (see the module text).

    `allowed`: folders whose files are not reported (the store folder: the
    caller scans it after close). Each other regular file that is open is
    read (up to 256 MB, with `pread`, so the offset of its owner does not
    move) and scanned for the needles.

    `thread`: also poll from a background thread each `interval` seconds.
    `polls` counts all polls; `hooked` counts the polls of `progress` only,
    so a test can show that the watch ran inside the statements that it
    checks, whatever the load on the machine."""

    def __init__(
        self,
        needles: Sequence[bytes],
        allowed: Iterable[str | Path] = (),
        interval: float = 0.001,
        *,
        thread: bool = True,
    ) -> None:
        self.needles = list(needles)
        self.allowed = [str(Path(a).resolve()) for a in allowed]
        self.interval = interval
        self.files: dict[str, OpenFile] = {}
        self.polls = 0
        self.hooked = 0
        self._seen: dict[tuple[int, int], tuple[int, int, int]] = {}
        self._lock = threading.Lock()  # the thread and the hooks share the state
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True) if thread else None

    def __enter__(self) -> FdWatch:
        if self._thread is not None:
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()

    def _allowed(self, path: str) -> bool:
        real = os.path.realpath(path)
        return any(real == a or real.startswith(a + os.sep) for a in self.allowed)

    def _look(self, fd: int) -> None:
        try:
            st = os.fstat(fd)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode):
            return
        # A file that has not changed since the last read is not read again
        # (a busy process holds many open files; each poll must stay short).
        key = (st.st_dev, st.st_ino)
        state = (st.st_size, st.st_mtime_ns, len(self.needles))
        if self._seen.get(key) == state:
            return
        self._seen[key] = state
        path = _fd_path(fd)
        if path is None:  # some systems give no path for a deleted file
            path = f"<deleted file: device {st.st_dev}, inode {st.st_ino}>"
        elif self._allowed(path) or path.endswith(CODE):
            return
        rec = self.files.setdefault(path, OpenFile(path, st.st_nlink == 0, 0))
        rec.deleted = rec.deleted or st.st_nlink == 0
        rec.size = max(rec.size, st.st_size)
        try:
            data = os.pread(fd, min(st.st_size, MAX_READ), 0)
        except OSError:
            return
        rec.hits |= _find(data, self.needles)

    def poll(self) -> None:
        """Read each open file of the process once, now."""
        with self._lock:
            self.polls += 1
            for fd in _open_fds():
                self._look(fd)

    def progress(self) -> int:
        """A SQLite progress handler (`set_progress_handler`): a poll inside
        the statement that runs, while its temp files are open. The return
        value 0 lets the statement go on."""
        self.poll()
        with self._lock:
            self.hooked += 1
        return 0

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll()
            self._stop.wait(self.interval)

    def plaintext(self) -> list[OpenFile]:
        """The watched files that held a needle."""
        with self._lock:
            return [f for f in self.files.values() if f.hits]
