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


def scan(
    since: float, needles: Iterable[bytes], root: Path, max_depth: int | None = None
) -> list[Path]:
    """The files under `root` (to `max_depth` folder levels, None: all) that
    changed at or after `since` and hold a needle."""
    needles = [n for n in needles if n]
    hits: list[Path] = []
    base_depth = len(root.parts)
    for base, subdirs, files in os.walk(root, onerror=lambda _e: None):
        if max_depth is not None and len(Path(base).parts) - base_depth >= max_depth:
            subdirs.clear()
        for name in files:
            data = _read(Path(base) / name, since)
            if data is not None and any(n in data for n in needles):
                hits.append(Path(base) / name)
    return hits


@contextlib.contextmanager
def no_plaintext_temp(*canaries: str) -> Iterator[None]:
    """Fail if a temp file that changed in the block holds a canary (UTF-8
    or UTF-16 LE, the forms that Office and PDF tools write)."""
    real = Path(tempfile.gettempdir()).resolve()
    box = Path(tempfile.mkdtemp(prefix="tempscan-")).resolve()
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
    hits = scan(start, needles, box)
    for d in FIXED_DIRS:
        if Path(d).is_dir():
            hits += scan(start, needles, Path(d).resolve())
    hits += scan(start, needles, real, max_depth=2)
    shutil.rmtree(box, ignore_errors=True)
    assert not hits, f"plaintext temp files hold a canary: {hits}"
