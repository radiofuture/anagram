"""Temp-file canary scan (net 01 step 4, net 02 step 2; review finding M6).

Put a unique canary string in the input, run the code under the
`no_plaintext_temp` context, and the test fails if a temp file that changed
during the run holds a canary. It finds a converter or a store that writes
plaintext temp files.

The OS temp directory on macOS (`/var/folders/.../T`) can hold hundreds of
thousands of files, and a full walk takes about 30 s. So the block runs with
`TMPDIR` and `tempfile.tempdir` set to a new empty folder, and the scan reads:

- that folder (all of it): `tempfile`, and tools that read `TMPDIR`;
- `/tmp` and `/var/tmp` (all of it): tools with a fixed path;
- the real temp directory to depth 2: tools that ask the OS for it.

Only files that changed after the start are read, so other processes in the
same directories do not slow the scan much, and they cannot hold a random
canary.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import tempfile
import time
from collections.abc import Iterable, Iterator
from pathlib import Path

MAX_READ = 64 * 1024 * 1024
FIXED_DIRS = ("/tmp", "/var/tmp")  # noqa: S108
_SKIP_PREFIXES = ("pytest-of-", "tempscan-")


def canary(label: str = "canary") -> str:
    return f"{label}-{secrets.token_hex(8)}"


def _read(path: Path, since: float) -> bytes | None:
    try:
        st = path.lstat()
        if not path.is_file() or path.is_symlink() or st.st_mtime < since:
            return None
        with path.open("rb") as fh:
            return fh.read(MAX_READ)
    except OSError:
        return None


def _has_needle(path: Path, since: float, needles: list[bytes]) -> bool:
    data = _read(path, since)
    return data is not None and any(n in data for n in needles)


def scan(
    since: float, needles: Iterable[bytes], root: Path, max_depth: int | None = None
) -> list[Path]:
    """The files under `root` (to `max_depth` folder levels, None: all) that
    changed at or after `since` and hold a needle."""
    needle_list = [n for n in needles if n]
    hits: list[Path] = []
    base_depth = len(root.parts)
    for base, subdirs, files in os.walk(root, onerror=lambda _e: None):
        subdirs[:] = [d for d in subdirs if not d.startswith(_SKIP_PREFIXES)]
        if max_depth is not None and len(Path(base).parts) - base_depth >= max_depth:
            subdirs.clear()
        for name in files:
            path = Path(base) / name
            if _has_needle(path, since, needle_list):
                hits.append(path)
    return hits


def _snapshot(root: Path) -> dict[str, tuple[bool, int, int]]:
    """Top-level entries of `root`: name -> (is_dir, st_mtime_ns, st_size).
    Skips symlinks and pytest/tempscan worker directories."""
    snap: dict[str, tuple[bool, int, int]] = {}
    try:
        with os.scandir(root) as it:
            for entry in it:
                if entry.name.startswith(_SKIP_PREFIXES):
                    continue
                try:
                    if entry.is_symlink():
                        continue
                    st = entry.stat(follow_symlinks=False)
                    snap[entry.name] = (
                        entry.is_dir(follow_symlinks=False),
                        st.st_mtime_ns,
                        st.st_size,
                    )
                except OSError:
                    continue
    except OSError:
        pass
    return snap


def _scan_external(
    root: Path,
    before: dict[str, tuple[bool, int, int]],
    since: float,
    needles: list[bytes],
    max_depth: int | None = None,
) -> list[Path]:
    """Scan only files and subdirectories in `root` that appeared or changed
    since `before`. Avoids walking hundreds of thousands of untouched OS temp
    files while catching any temp file or folder written during the block."""
    hits: list[Path] = []
    try:
        with os.scandir(root) as it:
            entries = list(it)
    except OSError:
        return hits
    for entry in entries:
        if entry.name.startswith(_SKIP_PREFIXES):
            continue
        try:
            if entry.is_symlink():
                continue
            st = entry.stat(follow_symlinks=False)
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        prev = before.get(entry.name)
        path = Path(entry.path)
        if is_dir:
            if prev is None:
                # Newly created directory during the block: scan all of it.
                hits.extend(scan(0.0, needles, path))
            elif not prev[0] or prev[1] != st.st_mtime_ns:
                # Existing directory modified during the block.
                sub_depth = None if max_depth is None else max(max_depth - 1, 0)
                hits.extend(scan(since, needles, path, max_depth=sub_depth))
        else:
            if prev is None or prev[0] or prev[1] != st.st_mtime_ns or prev[2] != st.st_size:
                if _has_needle(path, 0.0, needles):
                    hits.append(path)
    return hits


@contextlib.contextmanager
def no_plaintext_temp(*canaries: str) -> Iterator[None]:
    """Fail if a temp file that changed in the block holds a canary (UTF-8
    or UTF-16 LE, the forms that Office and PDF tools write)."""
    real = Path(tempfile.gettempdir()).resolve()
    box = Path(tempfile.mkdtemp(prefix="tempscan-")).resolve()
    external: list[tuple[Path, int | None]] = []
    seen: set[Path] = set()
    for d in FIXED_DIRS:
        p = Path(d)
        try:
            if p.is_dir():
                rp = p.resolve()
                if rp not in seen:
                    seen.add(rp)
                    external.append((rp, None))
        except OSError:
            continue
    try:
        if real not in seen and real.is_dir():
            external.append((real, 2))
    except OSError:
        pass
    snapshots = [(root, depth, _snapshot(root)) for root, depth in external]
    old_env, old_tempdir = os.environ.get("TMPDIR"), tempfile.tempdir
    os.environ["TMPDIR"] = str(box)
    tempfile.tempdir = str(box)
    start = time.time() - 1.0
    try:
        yield
    finally:
        tempfile.tempdir = old_tempdir
        if old_env is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_env
    needles = [c.encode("utf-8") for c in canaries] + [c.encode("utf-16-le") for c in canaries]
    hits = scan(0.0, needles, box)
    for root, depth, before in snapshots:
        hits += _scan_external(root, before, start, needles, max_depth=depth)
    shutil.rmtree(box, ignore_errors=True)
    assert not hits, f"plaintext temp files hold a canary: {hits}"
