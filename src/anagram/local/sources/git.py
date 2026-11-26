"""Local Git repository connector.

Each commit reachable from HEAD is one evidence item (a record, not a file).
The record holds the Git commit ID and tree ID as labels, and our own SHA-256
tree hash, so a proof does not depend on Git SHA-1:

    tree_sha256 = SHA-256(canonical_json([[path, mode, sha256(blob)], ...]))

Blobs are read once per scan through `git cat-file --batch` and cached by blob
ID. The connector does not hash pack files or the whole history. A commit that
the index already knows is not read again (a commit never changes).

The newest commit also carries a repository summary (README and file list) as
an extraction hint. The hint is derived meaning, not evidence.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess  # git is called with fixed arguments only
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path

from anagram.core.canonical import canonical_json
from anagram.core.crypto.chunked import ContentDigest
from anagram.local.index.extract import repo_summary
from anagram.local.sources.base import (
    Connector,
    ConnectorError,
    EvidenceItem,
    KnownItem,
    SourceContext,
    Suggestion,
    record_item,
)
from anagram.local.sources.folder import FolderConnector

COMMIT_KIND = "git_commit"


# A repository that a user indexes can come from someone else, and its
# .git/config can name programs. These values have the priority of `git -c`, so
# they replace the repository values. The connector also runs only commands that
# read objects (log, ls-tree, cat-file), never the working tree or the index.
SAFE_CONFIG = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("core.pager", "cat"),
    ("core.sshCommand", "false"),
    ("core.askPass", ""),
    ("credential.helper", ""),
    ("protocol.allow", "never"),
    ("diff.external", ""),
    ("log.showSignature", "false"),
    ("gpg.program", "false"),
    ("gpg.ssh.program", "false"),
    ("gpg.x509.program", "false"),
    ("safe.bareRepository", "explicit"),
)


def git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "GIT_ASKPASS": "",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_CONFIG_COUNT": str(len(SAFE_CONFIG)),
            "LC_ALL": "C",
        }
    )
    for i, (key, value) in enumerate(SAFE_CONFIG):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


def _utc(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class GitConnector(Connector):
    kind = "git"
    label = "Git repository"

    @classmethod
    def from_config(cls, cfg: dict, ctx: SourceContext) -> GitConnector:
        return cls(cfg["repo"], cfg.get("rev", "HEAD"))

    @classmethod
    def discover(cls, path: Path) -> list[Suggestion]:
        """Git repositories at or under `path` (folders with a `.git` entry)."""

        p = Path(path).expanduser()
        if not p.is_dir():
            return []
        out = []
        for repo in FolderConnector(p).repositories():
            git = cls(repo)
            out.append(Suggestion(cls.kind, git.describe(), git.config()))
        return out

    def __init__(self, repo: str | Path, rev: str = "HEAD") -> None:
        self.repo = Path(repo).resolve()
        self.rev = rev
        self._git = shutil.which("git")
        self._env = git_env()

    def config(self) -> dict:
        return {"kind": self.kind, "repo": str(self.repo), "rev": self.rev}

    def describe(self) -> str:
        return f"git {self.repo}"

    def _run(self, *args: str, data: bytes | None = None) -> bytes:
        if self._git is None:
            raise ConnectorError("git is not available")
        res = subprocess.run(  # noqa: S603 - fixed program, no shell
            [self._git, "-C", str(self.repo), *args],
            input=data,
            env=self._env,
            capture_output=True,
            check=False,
        )
        if res.returncode != 0:
            raise ConnectorError(f"git {args[0]} failed: {res.stderr.decode(errors='replace')}")
        return res.stdout

    def commits(self) -> list[dict]:
        fmt = "%H%x00%T%x00%P%x00%an%x00%aI%x00%cI%x00%B%x1e"
        out = self._run(
            "log", "--no-show-signature", "--reverse", f"--format={fmt}", self.rev, "--"
        )
        commits = []
        for rec in out.decode("utf-8", "replace").split("\x1e"):
            rec = rec.lstrip("\n")
            if not rec:
                continue
            sha, tree, parents, author, atime, ctime, message = rec.split("\x00", 6)
            commits.append(
                {
                    "author": author,
                    "author_time": _utc(atime),
                    "commit": sha,
                    "committer_time": _utc(ctime),
                    "message": message.strip(),
                    "parents": parents.split(),
                    "tree": tree,
                }
            )
        return commits

    def _tree(self, commit: str) -> list[tuple[str, str, str]]:
        out = self._run("ls-tree", "-r", "-z", "--full-tree", commit)
        entries = []
        for rec in out.split(b"\0"):
            if not rec:
                continue
            meta, path = rec.split(b"\t", 1)
            mode, otype, oid = meta.decode().split()
            if otype == "blob":
                entries.append((path.decode("utf-8", "surrogateescape"), mode, oid))
        return sorted(entries)

    def _blob_hashes(self, oids: list[str], cache: dict[str, str]) -> None:
        todo = sorted({o for o in oids if o not in cache})
        if not todo:
            return
        out = self._run("cat-file", "--batch", data=("\n".join(todo) + "\n").encode())
        pos = 0
        for oid in todo:
            nl = out.index(b"\n", pos)
            header = out[pos:nl].decode().split()
            size = int(header[2])
            body = out[nl + 1 : nl + 1 + size]
            cache[oid] = hashlib.sha256(body).hexdigest()
            pos = nl + 1 + size + 1

    def tree_sha256(self, commit: str, cache: dict[str, str]) -> tuple[str, int]:
        entries = self._tree(commit)
        self._blob_hashes([oid for _, _, oid in entries], cache)
        rows = [[path, mode, cache[oid]] for path, mode, oid in entries]
        return hashlib.sha256(canonical_json(rows)).hexdigest(), len(rows)

    def scan(self, known: Mapping[str, KnownItem]) -> Iterator[EvidenceItem]:
        if self._git is None:
            return
        try:
            commits = self.commits()
        except ConnectorError:
            return  # empty repository or bad revision: no items
        cache: dict[str, str] = {}
        for i, c in enumerate(commits):
            head = i == len(commits) - 1
            key = c["commit"]
            prev = known.get(key)
            if prev is not None and not head:
                yield EvidenceItem(
                    key=key,
                    kind=COMMIT_KIND,
                    name=c["message"].splitlines()[0] if c["message"] else None,
                    media_type="application/json",
                    digest=ContentDigest.from_json(prev.digest),
                    ref=f"git:{key}",
                    time=c["committer_time"],
                )
                continue
            tree_hash, n_files = self.tree_sha256(key, cache)
            record = {**c, "files": n_files, "tree_sha256": tree_hash}
            extra = {}
            if head:
                extra["summary"] = repo_summary(self.repo, self._git, self._env).to_json()
            yield record_item(
                key=key,
                kind=COMMIT_KIND,
                name=c["message"].splitlines()[0] if c["message"] else None,
                ref=f"git:{key}",
                record=record,
                text=c["message"],
                title=c["message"].splitlines()[0] if c["message"] else None,
                prose=True,
                time=c["committer_time"],
                extra=extra,
            )
