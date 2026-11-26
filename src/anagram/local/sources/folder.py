"""Local folder connector (also Dropbox, Google Drive, OneDrive, and Box sync
folders). Read-only. "Watch" is a scan: the index runs a scan on a schedule or
when the user asks.

- Each regular file is one evidence item. Key: the path relative to the root
  (POSIX form).
- Change detection: if size and mtime are the same as at the last scan, the
  connector keeps the last digest. Otherwise it hashes the file again
  (chunked SHA-256). The index then compares digests.
- The config key `exclude` (optional) lists folders, as POSIX paths relative
  to the root, that this source does not read (for example an Obsidian vault
  that is its own source).
- Ignored: `.git` internals (the Git connector reads repositories), other VCS
  folders, OS junk (`.DS_Store`, `Thumbs.db`, `desktop.ini`, `._*` resource
  forks, `~$*` Office lock files, `.~lock.*#`), and symbolic links (so a scan
  never leaves the root).
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator, Mapping
from pathlib import Path

from anagram.core.crypto.chunked import ContentDigest, hash_file
from anagram.local.index.media import sniff_file
from anagram.local.sources.base import Connector, EvidenceItem, KnownItem, SourceContext, Suggestion
from anagram.local.sources.http import SourceFault

IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".ipynb_checkpoints",
        ".Trash",
        ".Trashes",
        ".Spotlight-V100",
        ".fseventsd",
        ".dropbox.cache",
        "$RECYCLE.BIN",
        "System Volume Information",
    }
)
IGNORED_FILES = ("*.DS_Store", "Thumbs.db", "desktop.ini", "._*", "~$*", ".~lock.*#", "Icon\r")


def ignored_file(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in IGNORED_FILES)


class FolderConnector(Connector):
    kind = "folder"
    label = "Folder"

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> FolderConnector:
        return cls(cfg["root"], exclude=cfg.get("exclude", ()))

    @classmethod
    def discover(cls, path: Path) -> list[Suggestion]:
        p = Path(path).expanduser()
        if not p.is_dir():
            return []
        folder = cls(p)
        return [Suggestion(cls.kind, folder.describe(), folder.config())]

    def __init__(
        self,
        root: str | Path,
        chunk_size: int | None = None,
        *,
        exclude: tuple[str, ...] | list[str] = (),
        ignored_dirs: frozenset[str] = frozenset(),
    ) -> None:
        self.root = Path(root).resolve()
        self.chunk_size = chunk_size
        self.exclude = tuple(sorted({e.strip("/") for e in exclude if e.strip("/")}))
        self.ignored_dirs = IGNORED_DIRS | ignored_dirs

    def config(self) -> dict:
        cfg = {"kind": self.kind, "root": str(self.root)}
        if self.exclude:
            cfg["exclude"] = list(self.exclude)
        return cfg

    def _keep_dirs(self, dirpath: str, dirnames: list[str]) -> list[str]:
        """The folders of one walk step that this source reads, sorted."""
        keep = sorted(d for d in dirnames if d not in self.ignored_dirs)
        if not self.exclude:
            return keep
        here = Path(dirpath).relative_to(self.root)
        return [d for d in keep if (here / d).as_posix() not in self.exclude]

    def describe(self) -> str:
        return f"folder {self.root}"

    def files(self) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = self._keep_dirs(dirpath, dirnames)
            for name in sorted(filenames):
                if ignored_file(name):
                    continue
                p = Path(dirpath) / name
                if p.is_symlink() or not p.is_file():
                    continue
                yield p

    def repositories(self) -> list[Path]:
        """Git repositories under the root (folders with a `.git` entry)."""
        out = []
        for dirpath, dirnames, _ in os.walk(self.root, followlinks=False):
            if ".git" in dirnames or (Path(dirpath) / ".git").is_file():
                out.append(Path(dirpath))
            dirnames[:] = self._keep_dirs(dirpath, dirnames)
        return sorted(out)

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        if not self.root.is_dir():
            # A folder that is gone (an unplugged drive, a move) is a fault of
            # the source. Its items are not marked as removed.
            raise SourceFault("not_found", "the folder is gone")
        for p in self.files():
            rel = p.relative_to(self.root).as_posix()
            st = p.stat()
            prev = known.get(rel)
            same = prev is not None and prev.size == st.st_size and prev.mtime_ns == st.st_mtime_ns
            if same:
                digest = ContentDigest.from_json(prev.digest)
            else:
                digest = hash_file(p, self.chunk_size)
            media_type = prev.media_type if same and prev.media_type else sniff_file(p)
            yield EvidenceItem(
                key=rel,
                kind="file",
                name=p.name,
                media_type=media_type,
                digest=digest,
                ref=rel,
                mtime_ns=st.st_mtime_ns,
                path=p,
            )
